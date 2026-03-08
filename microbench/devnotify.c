/*
 * devnotify.c — Measure virtio device-notification cost in CPU cycles.
 *
 * Reproduces the "DevNotify" row of Table 3 in the DVH ASPLOS'20 paper.
 * "Device notification via MMIO write from VM virtio device driver to
 *  virtual I/O device."
 *
 * How it works:
 *   The virtio driver notifies the host that a new request is available
 *   by writing the queue index to a "notify" register.  In modern
 *   virtio-PCI this register lives in a memory-mapped BAR; in legacy
 *   virtio-PCI it is an I/O port.  Both variants cause a VM-exit so the
 *   host hypervisor can service the request.  We map the register from
 *   user-space and measure the write cost with RDTSC.
 *
 * Requirements:
 *   - Run as root (needs open /sys/bus/pci/devices/.../resource<N> RDWR,
 *     or /dev/mem for legacy I/O-port fallback via ioperm).
 *   - Run INSIDE the target VM.
 *
 * Build:  gcc -O2 -o devnotify devnotify.c
 * Run:    sudo ./devnotify
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/io.h>      /* ioperm, outw — legacy fallback */
#include <sched.h>

#define ITERATIONS 10000
#define WARMUP     1000

/* Virtio PCI vendor/device IDs */
#define VIRTIO_VENDOR           0x1af4u
/* Legacy net=0x1000, legacy blk=0x1001; modern net=0x1041, modern blk=0x1042 */

/* Virtio PCI capability type for the notification config */
#define VIRTIO_PCI_CAP_NOTIFY_CFG  2
#define PCI_CAP_ID_VNDR           0x09

/* Legacy virtio I/O-port offsets (BAR 0, I/O space) */
#define VIRTIO_PCI_QUEUE_NOTIFY   0x10

static inline uint64_t rdtsc_ordered(void)
{
	uint32_t lo, hi;
	asm volatile("lfence\n\trdtsc" : "=a"(lo), "=d"(hi) :: "memory");
	return ((uint64_t)hi << 32) | lo;
}

/* ── PCI config helpers ─────────────────────────────────────────────────── */

static uint8_t  cfg8 (const uint8_t *c, int off) { return c[off]; }
static uint16_t cfg16(const uint8_t *c, int off) { return *(const uint16_t*)(c+off); }
static uint32_t cfg32(const uint8_t *c, int off) { return *(const uint32_t*)(c+off); }

/* ── Find the first virtio PCI device ────────────────────────────────────── */

static int find_virtio_dev(char *out_path, size_t out_len)
{
	DIR *d = opendir("/sys/bus/pci/devices");
	if (!d) return -1;

	struct dirent *de;
	while ((de = readdir(d)) != NULL) {
		if (de->d_name[0] == '.') continue;

		char path[512];
		snprintf(path, sizeof(path),
			 "/sys/bus/pci/devices/%s/vendor", de->d_name);
		FILE *f = fopen(path, "r");
		if (!f) continue;
		unsigned vendor = 0;
		fscanf(f, "%x", &vendor);
		fclose(f);

		if (vendor != VIRTIO_VENDOR) continue;

		snprintf(out_path, out_len,
			 "/sys/bus/pci/devices/%s", de->d_name);
		closedir(d);
		return 0;
	}
	closedir(d);
	return -1;
}

/* ── Read 256-byte PCI config space via sysfs ────────────────────────────── */

static int read_pci_config(const char *dev_path, uint8_t cfg[256])
{
	char path[512];
	snprintf(path, sizeof(path), "%s/config", dev_path);
	int fd = open(path, O_RDONLY);
	if (fd < 0) { perror("open config"); return -1; }
	ssize_t n = read(fd, cfg, 256);
	close(fd);
	return (n == 256) ? 0 : -1;
}

/* ── Modern virtio: walk PCI caps to find the notify BAR/offset ──────────── */

static int find_notify_cap(const uint8_t cfg[256],
			    int *out_bar,
			    uint32_t *out_offset,
			    uint32_t *out_multiplier)
{
	uint8_t cap = cfg8(cfg, 0x34) & 0xFC;
	while (cap >= 0x40) {
		uint8_t id   = cfg8(cfg, cap);
		uint8_t next = cfg8(cfg, cap + 1);
		uint8_t len  = cfg8(cfg, cap + 2);

		if (id == PCI_CAP_ID_VNDR && len >= 16) {
			uint8_t type = cfg8(cfg, cap + 3);
			if (type == VIRTIO_PCI_CAP_NOTIFY_CFG) {
				*out_bar        = cfg8 (cfg, cap +  4);
				*out_offset     = cfg32(cfg, cap +  8);
				*out_multiplier = cfg32(cfg, cap + 16);
				return 0;
			}
		}
		cap = next & 0xFC;
	}
	return -1;
}

/* ── Get BAR size from the sysfs "resource" file ─────────────────────────── */

static size_t get_bar_size(const char *dev_path, int bar_idx)
{
	char path[512];
	snprintf(path, sizeof(path), "%s/resource", dev_path);
	FILE *f = fopen(path, "r");
	if (!f) return 0;

	unsigned long start = 0, end = 0, flags = 0;
	for (int i = 0; i <= bar_idx; i++)
		fscanf(f, "%lx %lx %lx", &start, &end, &flags);
	fclose(f);
	return (end > start) ? (size_t)(end - start + 1) : 0;
}

/* ── Main ────────────────────────────────────────────────────────────────── */

int main(void)
{
	cpu_set_t cs;
	CPU_ZERO(&cs);
	CPU_SET(0, &cs);
	sched_setaffinity(0, sizeof(cs), &cs);

	char dev_path[512];
	if (find_virtio_dev(dev_path, sizeof(dev_path)) < 0) {
		fprintf(stderr, "No virtio PCI device found\n");
		return 1;
	}
	printf("virtio device: %s\n", dev_path);

	uint8_t cfg[256];
	if (read_pci_config(dev_path, cfg) < 0) {
		fprintf(stderr, "Cannot read PCI config\n");
		return 1;
	}

	int          notify_bar = -1;
	uint32_t     notify_offset = 0, notify_multiplier = 0;
	int          modern = 0;

	if (find_notify_cap(cfg, &notify_bar,
			    &notify_offset, &notify_multiplier) == 0) {
		modern = 1;
		printf("Modern virtio: notify BAR=%d offset=0x%x multiplier=%u\n",
		       notify_bar, notify_offset, notify_multiplier);
	} else {
		printf("No modern notify cap — trying legacy I/O-port path\n");
	}

	uint64_t start, end;

	if (modern) {
		/* Map the notification BAR via sysfs resource file */
		char res_path[512];
		snprintf(res_path, sizeof(res_path),
			 "%s/resource%d", dev_path, notify_bar);

		size_t bar_size = get_bar_size(dev_path, notify_bar);
		if (bar_size == 0) {
			fprintf(stderr, "Cannot determine BAR size\n");
			return 1;
		}

		int fd = open(res_path, O_RDWR | O_SYNC);
		if (fd < 0) {
			perror("open resource (need root)");
			return 1;
		}

		void *map = mmap(NULL, bar_size,
				 PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		close(fd);
		if (map == MAP_FAILED) { perror("mmap"); return 1; }

		/*
		 * Queue 0 notify register.
		 * notify_off for queue 0 is always 0 in the standard layout.
		 */
		volatile uint16_t *reg = (volatile uint16_t *)
			((char *)map + notify_offset +
			 0 /* queue_notify_off=0 */ * notify_multiplier);

		for (int i = 0; i < WARMUP; i++) {
			*reg = 0;
			asm volatile("" ::: "memory");
		}

		start = rdtsc_ordered();
		for (int i = 0; i < ITERATIONS; i++) {
			*reg = 0;
			asm volatile("" ::: "memory");
		}
		end = rdtsc_ordered();

		munmap(map, bar_size);
	} else {
		/* Legacy path: BAR 0 is I/O space; notify at base+0x10 */
		uint32_t bar0 = cfg32(cfg, 0x10);
		if (!(bar0 & 1)) {
			fprintf(stderr, "BAR 0 is not I/O space — giving up\n");
			return 1;
		}
		uint16_t io_base     = bar0 & 0xFFFC;
		uint16_t notify_port = io_base + VIRTIO_PCI_QUEUE_NOTIFY;

		if (ioperm(notify_port, 2, 1) < 0) {
			perror("ioperm (need root)");
			return 1;
		}

		for (int i = 0; i < WARMUP; i++)
			asm volatile("outw %0,%1"
				:: "a"((uint16_t)0), "Nd"(notify_port)
				: "memory");

		start = rdtsc_ordered();
		for (int i = 0; i < ITERATIONS; i++)
			asm volatile("outw %0,%1"
				:: "a"((uint16_t)0), "Nd"(notify_port)
				: "memory");
		end = rdtsc_ordered();
	}

	printf("DevNotify: %lu cycles avg  (%d iterations)\n",
	       (end - start) / ITERATIONS, ITERATIONS);
	printf("Paper reference — VM: 4,984  nested VM: 48,390  L3 VM: 1,008,935\n");
	return 0;
}
