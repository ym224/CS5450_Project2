//
// Created by Yunie Mao on 10/17/17.
//

ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags)
{
    /* Hint: Check the data length field 'len'.
     *       If it is > DATALEN, you will have to split the data
     *       up into multiple packets - you don't have to worry
     *       about getting more than N * DATALEN.
     */

    int cur_mode = machine.mode;
    int cur_seq = rand();

    machine.seqnum = cur_seq;

    int remaining = len;
    int cur_size = 0;
    int track = 0;
    int attempts;


    char * tempBuf = (char *) malloc(DATALEN * sizeof(char));
    /*Keep sending till end of file*/
    while (track < len) {

        /* Clear the packet buffer*/
        memset(tempBuf, '\0', DATALEN);

        if (remaining >= DATALEN) {
            cur_size = DATALEN;
        }
        else {
            cur_size = remaining;
        }

        /* SLOW*/
        attempts = 0;
        if (cur_mode == SLOW) {
            printf("Sending slow\n");
            gbnhdr * nextPack;
            gbnhdr * rec_buf;

            memcpy(tempBuf, buf + track, cur_size);

            while(machine.state != ACK_RCVD && attempts < 5) {
                nextPack = make_packet(DATA, cur_seq, tempBuf, cur_size);


                int rtn = sendto(sockfd, nextPack, sizeof(*nextPack), 0, clientAddr, clientLen);

                if (rtn == -1) {
                    printf("Failed to send packet, attempt: %d\n", ++attempts);
                    continue;
                }

                machine.state = DATA_SENT;
                alarm(TIMEOUT);
                printf("Sent packet, waiting for response...\n");
                rec_buf = malloc(sizeof(gbnhdr));
                int rec_size = recvfrom(sockfd, rec_buf, sizeof(gbnhdr), 0, hostAddr, &hostLen);


                if(check_packet(rec_buf, DATAACK, rec_size) == 0){
                    machine.state = ACK_RCVD;
                    cur_mode = FAST;
                    track += cur_size;
                    remaining = remaining - cur_size;
                    cur_seq++;
                    machine.seqnum = cur_seq;
                } else {
                    attempts++;
                }

            }

            /* Close out after 5 attempts*/
            if (machine.state == DATA_SENT) {
                printf("Failed after %d attempts\n", attempts);
                return -1;
            }

            free(nextPack);
            free(rec_buf);
            machine.state = ESTABLISHED;
        } else { /* FAST*/
            printf("Sending fast\n");
            memcpy(tempBuf, buf + track, cur_size);
            machine.state = ESTABLISHED;

            int firstTrack = track;
            int firstLen  = cur_size;
            int firstSeqnum = cur_seq;

            /* send first packet*/
            gbnhdr * firstPack = make_packet(DATA, cur_seq, tempBuf, cur_size);

            sendto(sockfd, firstPack,
                   sizeof(*firstPack), 0, hostAddr, hostLen);

            machine.state = DATA_SENT;


            /* Clear the buffer*/
            memset(tempBuf, '\0', DATALEN);

            /* Send second only if theres still remaining buffer*/
            int secondTrack;
            int secondLen;
            int secondSeqnum;
            if (track + cur_size < len) {
                cur_seq++;
                machine.seqnum = cur_seq;
                track += cur_size;

                secondTrack = track;
                secondSeqnum = cur_seq;

                /* Check size*/
                if (remaining >= DATALEN*2) {
                    secondLen = DATALEN;
                }
                else {
                    secondLen = remaining - DATALEN;
                }

                memcpy(tempBuf, buf + track, cur_size);
                gbnhdr * secondPack = make_packet(DATA, cur_seq, tempBuf, cur_size);

                sendto(sockfd, secondPack,
                       sizeof(*secondPack), 0, hostAddr, hostLen);

            }
            else {
                secondSeqnum = cur_seq;
                secondLen = firstLen;
            }

            cur_seq = firstSeqnum;
            gbnhdr * rec_buf;
            while(attempts < 5 && machine.state != ACK_RCVD){
                alarm(TIMEOUT);
                rec_buf = malloc(sizeof(gbnhdr));
                int rec_size = recvfrom(sockfd, rec_buf, sizeof * rec_buf, 0, hostAddr, &hostLen);

                if(check_packet(rec_buf, DATAACK, rec_size) ==0){
                    if(rec_buf->seqnum == secondSeqnum) {
                        printf("Ack second packet, seqnum: %d\n", rec_buf->seqnum);
                        machine.state = ACK_RCVD;
                        track += secondLen;
                        remaining -= (secondLen);
                        cur_seq++;
                        machine.seqnum = cur_seq;
                    }
                    else if(rec_buf->seqnum == firstSeqnum) {
                        printf("Ack first packet, seqnum: %d\n", rec_buf->seqnum);
                        remaining -= firstLen;
                        cur_seq = secondSeqnum;
                    }
                    else {
                        attempts++;
                        continue;
                    }
                } else {
                    if (rec_buf->seqnum == firstSeqnum) {
                        cur_mode = SLOW;
                        track = firstTrack;
                        cur_seq = firstSeqnum;
                        break;
                    }
                    else if (rec_buf->seqnum == secondSeqnum && cur_seq == secondSeqnum){
                        cur_mode = SLOW;
                        track = secondTrack;
                        break;
                    }
                    else {
                        attempts++;
                    }
                }
                free(rec_buf);
            }
            /* Start over again with first packer */
            if (attempts == 5) {
                cur_mode = SLOW;
                track = firstTrack;
                cur_seq = firstSeqnum;
            }
        }
    }
    machine.isFin = 1;
    printf("Finished sending, remaining %d\n", attempts);
    return remaining;
}