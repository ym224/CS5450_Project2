#include "gbn.h"

state_t s;
uint16_t checksum(uint16_t *buf, int nwords)
{
	uint32_t sum;

	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

void sig_handler(int signum){
	s.timed_out = 0;
	printf("Received signal %d\n", signum);
}

gbnhdr * make_packet(uint8_t type, uint8_t seqnum, int isHeader, char *buffer, int datalen){
	gbnhdr *packet = malloc(sizeof(gbnhdr));
	packet->type = type;
	packet->seqnum = seqnum;

    // if just a header, ignore check sum
	if (isHeader == 0) {
		packet->checksum = 0;
	}
    // otherwise set checksum
	else {
		memcpy(packet->data, buffer, sizeof(buffer));

		packet->checksum = checksum((uint16_t *) buffer, datalen);
	}
	return packet;
}

int check_packet(gbnhdr *packet, int type, int isHeader) {
	//check time out
	if (s.timed_out == 0) {
        // reset time out flag
        s.timed_out = 1;
        return -1;
    }

    // check packet type
    if (packet->type != type) {
		return -1;
	}

    // if not a header check sequence num
    if (isHeader != 0 && packet->seqnum < s.seqnum) {
        return -1;
    }

	return 0;
}

ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags){
	int attempts = 0;

	/* Hint: Check the data length field 'len'.
	 *       If it is > DATALEN, you will have to split the data
	 *       up into multiple packets - you don't have to worry
	 *       about getting more than N * DATALEN.
	 */

    // split data into multiple packets
    int numPackets = (int)len / DATALEN;
    if (len % DATALEN != 0) {
        numPackets ++;
    }
    char slicedBuf[DATALEN];
    for (int i=1; i<=numPackets; i++) {
        memcpy(slicedBuf, &buf[i*DATALEN], DATALEN);
        slicedBuf[DATALEN] = '\0';
        gbnhdr *packet, *rec_header;

        // slow mode
        if (s.mode == SLOW) {
            //while no ack received and retries not reached

            while (s.state != DATA_RCVD && attempts < 5) {

                // make packet with buffer data
                packet = make_packet(DATA, 0, -1, slicedBuf, DATALEN);
                if (sendto(sockfd, packet, sizeof(packet), flags, senderServerAddr, senderSocklen) == -1) {
                    attempts ++;
                    continue;
                }

                // start timer
                alarm(TIMEOUT);

                s.state = DATA_SENT;

                // receive ack header
                rec_header = malloc(sizeof(gbnhdr));

                recvfrom(sockfd, rec_header, sizeof(gbnhdr), 0, receiverServerAddr, &receiverSocklen);

                // check for timeout, verify header type and seqnum
                if (check_packet(rec_header, DATAACK, -1) == 0) {
                    s.state = DATA_RCVD;
                    // switch to fast
                    s.mode = FAST;
                    s.seqnum ++;
                }
                else {
                    attempts ++;
                }
                free(packet);
                free(rec_header);
            }

            // if data was sent 5 times without receiving dataack, return -1
            if (attempts == 5) {
                return -1;
            }
        }
        // fast mode
        else {
            gbnhdr * packet_one = make_packet(DATA, s.seqnum, -1, slicedBuf, DATALEN);

            // send
            if (sendto(sockfd, packet_one, sizeof(packet_one), flags, senderServerAddr, senderSocklen) == -1) {
                return -1;
            }

            // set state to data sent
            s.state = DATA_SENT;
            int firstSeqnum = s.seqnum;

            memset(slicedBuf, NULL, DATALEN);

            // only send second packet if there's remaining data
            if (i + 1 < numPackets) {
                s.seqnum ++ ;
                memcpy(slicedBuf, &buf[(i + 1) * DATALEN], DATALEN);
                gbnhdr *packet_second = make_packet(DATA, s.seqnum, -1, slicedBuf, DATALEN);
                sendto(sockfd, packet_second, sizeof(packet_second), flags, senderServerAddr, senderSocklen);
            }


            while (s.state != DATA_RCVD && attempts < 5) {
                alarm(TIMEOUT);

                rec_header = malloc(sizeof(gbnhdr));

                if (recvfrom(sockfd, rec_header, sizeof(rec_header), 0, receiverServerAddr, &receiverSocklen) == -1) {
                    attempts ++;
                    continue;
                }

                // verify time out, check header type
                if (check_packet(rec_header, DATAACK, -1) == 0){
                    // received ack for latest packet, all good
                    if (rec_header->seqnum == s.seqnum) {
                    s.state = DATA_RCVD;
                    s.seqnum++;
                    i ++;
                    }
                    // only received ack for first packet sent
                    else if (rec_header->seqnum == firstSeqnum) {
                        // need to resend starting with second packet
                    }
                    else {
                        attempts++;
                        continue;
                    }
                }
                else {
                    if (rec_header->seqnum == firstSeqnum) {
                        s.seqnum = (uint8_t )firstSeqnum;
                        s.mode = SLOW;
                    }
                    else {
                        attempts ++;
                    }

                }
            free(rec_header);
            }

            if (s.timed_out == 0 || attempts == 5) {
                // switch to slow mode
                s.mode = SLOW;
                s.timed_out = 1;
                // reset sequence #
            }
        }
    }
	s.state = CLOSED;

	return len;
}

ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags){

	// process buffer data
	printf ("gbn_recv: sockfd- %i, len %i, flags %i",sockfd, len, flags);

	gbnhdr * packet = malloc(sizeof(gbnhdr));

	recvfrom(sockfd, packet, sizeof(gbnhdr), 0, receiverServerAddr, &receiverSocklen);


    // if a data packet is received, check packet to verify its type and seqnum
	if (check_packet(packet, DATA, -1) == 0){
		printf("check packet successful");

		// check if data is corrupt
		if (checksum(buf, sizeof(packet->data)) == -1) {
			printf("check sum successful");
			return -1;
		}

		char rec_buf[DATALEN];
        memcpy(rec_buf, packet->data, sizeof(packet->data));

		// reply with dataack header with the seqnum sent
		gbnhdr *header = make_packet(DATAACK, packet->seqnum, 0, NULL, 0);

		if (sendto(sockfd, header, sizeof(gbnhdr), 0, receiverServerAddr, receiverSocklen) == -1) {
			printf ("inside sendto");
			return -1;
		}
		return sizeof(packet->data);
	}

    // if a connection teardown request is received, reply with FINACK header
	if (check_packet(packet, FIN, 0) == 0) {
		printf("reply with FINACK header");
		gbnhdr *header = make_packet(FINACK, 0, 0, NULL, 0);
		if (sendto(sockfd, header, sizeof(gbnhdr), 0, receiverServerAddr, receiverSocklen) == -1){
			return -1;
		}
		s.state = FIN_RCVD;
		return 0;
	}

	return -1;

}

int gbn_close(int sockfd){
	printf("inside gnb_close");
    // sender initiates connection teardown by sending a FIN header
	if (s.state == ESTABLISHED) {
		gbnhdr * header = make_packet(FIN, 0, 0, NULL, 0);
		if (sendto(sockfd, header, sizeof(gbnhdr), 0, senderServerAddr, senderSocklen) == -1){
            return -1;
        }
        s.state = FIN_SENT;
	}
	// if receiver sees a FIN header, reply with FINACK and close socket connection
	else if (s.state == FIN_SENT){
		gbnhdr * header = make_packet(FINACK, 0, 0, NULL, 0);

		if (sendto(sockfd, header, sizeof(gbnhdr), 0, receiverServerAddr, receiverSocklen) == -1){
            return -1;
        }
		close(sockfd);
	}
    return 0;
}

// client initiates connection by sending SYN to server
int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen){

    // pointer to local struct on sender server where receiver address is stored
    senderServerAddr = (struct sockaddr *)server;
    senderSocklen = socklen;

    // SIGALRM is called after timeout alarm
	signal(SIGALRM, sig_handler);

	if (sockfd < 0) {
		return -1;
	}

	gbnhdr *header = make_packet(SYN, 0, 0, NULL, 0);

	int attempt = 0;
	while (attempt < MAX_RETRIES) {
		// send SYN header to initialize connection
		if (sendto(sockfd, header, sizeof(header), 0, server, socklen) == -1 ) {
			attempt ++;
			continue;
		}

		s.state = SYN_SENT;

		// start timer and wait for ack

		alarm(TIMEOUT);

        gbnhdr *rec_header = malloc(sizeof(gbnhdr));
		// received an ack from receiver/server
		if (recvfrom(sockfd, rec_header, sizeof(rec_header), 0, receiverServerAddr, &receiverSocklen) < 0) {
            attempt ++;
            continue;
		}

        // check for timeout, check if header type is SYNACK
		if (check_packet(rec_header, SYNACK, 0) == 0) {
			s.state = ESTABLISHED;
			return 0;
		}
		attempt ++;
	}
	s.state = CLOSED;
	return -1;
}

int gbn_listen(int sockfd, int backlog){
    // wait for sender to initiate connection
	gbnhdr * header = malloc(sizeof(gbnhdr));

	if (recvfrom(sockfd, header, sizeof(gbnhdr), 0, receiverServerAddr, &receiverSocklen) == -1) {
		return -1;
	}
    // check if packet contains SYN header
	if (check_packet(header, SYN, 0) == 0) {
        s.state = SYN_RCVD;
        return 0;
    }
    return -1;
}

int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen){
    // pointer to local struct on receiver server where sender address is to be stored
    receiverServerAddr = (struct sockaddr *)server;
    receiverSocklen = socklen;

	return bind(sockfd, server, socklen);
}	

int gbn_socket(int domain, int type, int protocol){
		
	/*----- Randomizing the seed. This is used by the rand() function -----*/
	srand((unsigned)time(0));

	return socket(domain, type, protocol);
}

// receiver sends ack
int gbn_accept(int sockfd, struct sockaddr *client, socklen_t socklen){
    gbnhdr * header;
    // if connection teardown initiated, reject connection by sending RST
    if (s.state == FIN_SENT) {
         header = make_packet(RST, 0, 0, NULL, 0);
    }

    // accept connection initiation by sending header with SYNACK
    else {
        header = make_packet(SYNACK, 0, 0, NULL, 0);
    }

	if (sendto(sockfd, header, sizeof(header), 0, client, socklen) == -1) {
		return -1;
	}
	return sockfd;
}


ssize_t maybe_sendto(int  s, const void *buf, size_t len, int flags, \
                     const struct sockaddr *to, socklen_t tolen){

	char *buffer = malloc(len);
	memcpy(buffer, buf, len);
	
	
	/*----- Packet not lost -----*/
	if (rand() > LOSS_PROB*RAND_MAX){
		/*----- Packet corrupted -----*/
		if (rand() < CORR_PROB*RAND_MAX){
			
			/*----- Selecting a random byte inside the packet -----*/
			int index = (int)((len-1)*rand()/(RAND_MAX + 1.0));

			/*----- Inverting a bit -----*/
			char c = buffer[index];
			if (c & 0x01)
				c &= 0xFE;
			else
				c |= 0x01;
			buffer[index] = c;
		}

		/*----- Sending the packet -----*/
		int retval = sendto(s, buffer, len, flags, to, tolen);
		free(buffer);
		return retval;
	}
	/*----- Packet lost -----*/
	else
		return(len);  /* Simulate a success */
}
