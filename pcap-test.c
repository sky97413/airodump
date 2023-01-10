#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ncurses.h>
#include <unistd.h>


typedef struct {
	unsigned char bssid[7 + 1];
	int count;
	char essid[32 + 1];
} beaconInfo;

beaconInfo counters[30];
int beaconCount = 0;

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};


bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int checkDuplicate(const unsigned char* bssid) {
	for (int i = 0; i < beaconCount; i++) {
		if (strcmp(counters[i].bssid, bssid) == 0) {
			return i;
		}
	}
	return -1;
}


int main(int argc, char* argv[]) {
	initscr();

	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		int radioLen = packet[2];

		// skip non-beacon packets
		if (packet[radioLen + 0] != 0x80 || packet[radioLen + 1] != 0x00) continue;

		char bssid[6 + 1];
		memcpy(bssid, packet + radioLen + 16, 6);
		bssid[6] = '\0';

		// find the counter for this SSID, or create a new one
		int i = checkDuplicate(bssid);
		if (i < 0) {
			if (beaconCount == 30) continue; // skip if the counters are full
			// copy the SSID into a null-terminated string
			int essidOffset = radioLen + 37;
			int essidLen = packet[essidOffset];
			char essid[32 + 1];
			memcpy(essid, packet + essidOffset + 1, essidLen);
			essid[essidLen] = '\0';

			i = beaconCount++;
			strcpy(counters[i].essid, essid);
			memcpy(counters[i].bssid, bssid, 7);
			counters[i].count = 0;
		}

		// increment the counter
		counters[i].count++;

		clear();
		// print the counters
		printw("BSSID\t\t\tBeacons\t\t\t\t   ESSID\n");
		for (int i = 0; i < beaconCount; i++) {
			printw("%02x:%02x:%02x:%02x:%02x:%02x\t%d\t%32s\n", counters[i].bssid[0], counters[i].bssid[1], counters[i].bssid[2], counters[i].bssid[3], counters[i].bssid[4], counters[i].bssid[5], counters[i].count, counters[i].essid);
		refresh();
		}
	}

	pcap_close(pcap);
	endwin();
}

