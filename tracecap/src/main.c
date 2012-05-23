/*
* main.c
*
* Created on: 2011-03-11
* Author: chenxm
*/
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <getopt.h>
#include <string.h>
#include <netinet/in.h>
#include <unistd.h>	//used to set timer
#include <signal.h>
#include <time.h>

/*translate the time string into the value with unit of seconds*/
int get_time(char *time_string){
	int len = strlen(time_string);
	int time = 0;
	int i = 0;
	for (i = 0; i < len; i++){
		if ( i < len-1 && *(time_string+i) >= '0' && *(time_string+i) <= '9'){
			continue;
		}
		else if ( i == len -1 ){
			switch(*(time_string+i)){
				case 'h':
					time = atoi(time_string);
					return time * 60 *60;
				case 'm':
					time = atoi(time_string);
					return time * 60;
				case 's':
					time = atoi(time_string);
					return time;
				default:
					return (-1);
			}
		}
		else{
			return (-1);
		}
	}
}

/*show the information about how to use this program*/
void help(void){
	printf("tracecap\n");
	printf("\t--A simple network packet sniffering program.\n");
	printf("Usage:\n");
	printf("\t[-h] [-i interface] [-f filter] [-w write] [-t time]\n\n");
	printf("\t-h\n");
	printf("\t\t--Get help information. For more information please read the guide 'Readme.txt' in the root directory.\n\n");
	printf("\t-i INTERFACE\n");
	printf("\t\t--Set the network interface from which the packets are captured. Please make sure your network device is working correctly.\n\n");
	printf("\t-f FILTER STRING\n");
	printf("\t\t--Set the filter on the program to capture some interested packets. The knowledge about how to use the filter string correctly can be found in the guide 'Readme.txt' in the root directory.\n\n");
	printf("\t-w SAVED PATH\n");
	printf("\t\t--Set the saved path. We recommend you to finish the filename with suffix .pcap which is the default file format used by most sniffer programs like Wireshark. The defalut file name is <tc*.pcap>, where the * is replace with the UTC time when the program begins running.\n\n");
	printf("\t-t TIME\n");
	printf("\t\t--Set the time duration the program runs for. You must make sure the time value is integer and the format of TIME is finished with letter 'h', 'm' or 's', which means hour, minute or second seperately, i.e. '3m' means 3 minutes.\n\n");
}

pcap_t *handler = NULL; //returned by pcap_open_live()
int packet_num = 0;	//debugging variable
int time_in_seconds = 0;	//time duration

/*signal handler when the timeout expires*/
void handle_signal(){
	pcap_breakloop(handler);
}

/*the default packet-processing program which is the callback function of pcap_loop()*/
void process_packet(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet){

	if(time_in_seconds > 0){
		signal(SIGALRM, handle_signal);	//<signal.h>
		alarm(time_in_seconds);	//<unistd.h>--set the timmer
		time_in_seconds = 0;
	}

	packet_num ++;	//debugging variable
	printf(":%d\r", packet_num);

	pcap_dump(user, pkthdr, packet);	//dump the packet to file
}

/*the main function*/
int main( int argc, char **argv){

	/*analyze the options and obtain their arguments*/
	char *file_saved_path = NULL;	//where to save the file
	char *filter_rules = NULL;	//filter string used by pcap_setfilter()
	int help_flag = 0;
	int c = 0, r = 0;
	char *dev = NULL;	//network interface sniffered

	while ((c = getopt(argc, argv, "i:f:t:w:h")) != -1){
		switch (c){
			case 'i':
				dev = optarg;
				break;
			case 'f':
				filter_rules = optarg;
				break;
			case 't':
				r = get_time(optarg);
				if(r == -1){
					help();
					return (-1);
				}
				else if (r >= 0){
					time_in_seconds = r;
					break;
				}
				else{
					fprintf(stderr,"Could not get correct time! You can use '-h' for more information\n");
					return (-1);
				}
			case 'w':
				file_saved_path = optarg;
				break;
			case 'h':
				help_flag = 1;
				break;
			case '?':
				if (optopt == 'f' || optopt == 't' || optopt == 'w' || optopt == 'i')
					fprintf(stderr, "You can use '-h' for more information.\n");
				else if (isprint(optopt))
					fprintf(stderr, "You can use '-h' for more information.\n");
				else
					fprintf(stderr, "You can use '-h' for more information.\n");
				return (-1);
			default:
				help();
				return (-1);			
		}
	}
	
	/*prior to show help*/
	if (help_flag == 1){
		help();
		return (0);
	}
	
	/*capture packets*/
	char errbuf[PCAP_ERRBUF_SIZE];	//error buffer

	struct bpf_program fp;	//filter
	bpf_u_int32 net32;	//ip addr
	bpf_u_int32 mask32;	//net mask
	
	if(dev == NULL ){
		dev = pcap_lookupdev(errbuf);	//detect the available network device
	}
	if(dev == NULL){
		printf("%s\n", errbuf);
		printf("You can use '-h' for more information.\n");
		return (-1);
	}

	handler = pcap_open_live(dev, 65535, 0, 1000, errbuf); //open the network device
	if( handler == NULL){
		printf("%s\n",errbuf);
		printf("You can use '-h' for more information.\n");
		return (-1);
	}

	if ( pcap_lookupnet(dev, &net32, &mask32, errbuf) == -1){	//detect the ip addr and the mask addr which are both not used in this program
		printf("%s\n", errbuf);
		return (-1);
	}
	printf("DEV %s is opened successfully...\n", dev);

	if ( pcap_compile(handler, &fp, filter_rules, 0, mask32) == -1){	//complie the filter
		printf("Failed to set the filter program.\n%s\n", pcap_geterr(handler));
		return (-1);
	}
	if ( pcap_setfilter(handler, &fp) == -1){	//set the filter
		printf("Failed to specify the filter program.\n%s\n", pcap_geterr(handler));
		return (-1);
	}
	
	pcap_freecode(&fp);	//free the filter to recycle the resources

	/*dump the packets*/
	if (file_saved_path == NULL){
		time_t rawtime;
		char buff[25];
	
		time(&rawtime);
		sprintf(buff, "tc%d.pcap", (int)rawtime);	//default file name

		file_saved_path = buff;
	}

	printf("The packets are saved in %s\n",file_saved_path );
	printf("filter_rules = %s\n", filter_rules);
	
	pcap_dumper_t *pdumper;

	pdumper = pcap_dump_open(handler, file_saved_path);	//open the file to dump packets
	if ( pdumper == NULL ){
		printf("Can not open the file %s to save packets. Please check the path to make sure they exist.\n", file_saved_path);
		return (-1);
	}
	
	pcap_loop(handler, -1, process_packet, (unsigned char *)pdumper);	//loop to process packets

	printf("packet_num = %d\n", packet_num);	//debugging variable
	
	pcap_dump_flush(pdumper);
	pcap_dump_close(pdumper);

	pcap_close(handler);
	return (0);
}
