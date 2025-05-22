'''
    A basic traffic generator to determine:
        1. packets received.
        2. packets received out of order.
        3. packets missing.
        4. packets that are duplicates.

    A custom test protocol header is placed in the payload of ICMP packets, resulting in frames containing:
        [Ethernet II / IPv4 / ICMP / test protocol]

    The test protocol header used in the this traffic generator is as follows:

    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Source Physical Address               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+           
    |                         Sequence Number                       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Padding                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Where padding is added until the frame is 1400 bytes in length.

    Author: Peter Willis (pjw7904@rit.edu)
'''

from scapy.all import *
from subprocess import call
import time
import argparse
import sys

frameCounter = {} # Global dictionary to hold frame/packet payload content for analysis on the receiving end

def main():
    # ArgumentParser object to read in command line arguments
    argParser = argparse.ArgumentParser(description = "Basic traffic generator for protocol reconvergence testing purposes")

    # Sender arguments.
    argParser.add_argument("-s", "--send") # Destination (receiver) node
    argParser.add_argument("-c", "--count", type = int) # The number of frames to send.
    argParser.add_argument("-d", "--delay", type = float) # Add a delay when sending traffic.

    # Receiver arguments.
    argParser.add_argument("-r", "--receive") # Receive traffic to result.pcap by default
    argParser.add_argument("-a", "--analyze") # argument of capture needed

    # Shared arguments.
    argParser.add_argument("-e", "--port", default="eth1") # By default, it's eth1 on our testbeds.

    # Parse the arguments.
    args = argParser.parse_args()
    port = args.port

    # Receive traffic.
    if(args.receive):
        recvTraffic(port, args.receive)

    # Send traffic.
    elif(args.send):
        dstLogicalAddr = args.send
        count = args.count
        delay = args.delay
        sendTraffic(dstLogicalAddr, count, delay, port)

    # Analyze traffic.
    elif(args.analyze):
        captureFile = args.analyze
        print(f"Working on capture file {captureFile}...")
        analyzeTraffic(captureFile)

    else:
        sys.exit("Syntax error: incorrect arguments (use -h for help)") # Error out if the arguments are bad or missing.

    return None

def sendTraffic(dstLogicalAddr, count, delay, port):
    # Information needed to generate a custom payload and build protocol headers.
    srcPhysicalAddr = get_if_hwaddr(port)

    # Added UDP at the end to maybe calm this down a bit.
    PDUToSend = Ether(src = srcPhysicalAddr)/IP(dst = dstLogicalAddr)/ICMP(type=1)
    generateContinousTraffic(PDUToSend, count, srcPhysicalAddr, delay, port)

    return None

def generateContinousTraffic(PDUToSend, numberOfFramesToSend, srcPhysicalAddr, delay, port):
    # Constants.
    PAYLOAD_DELIMITER_SIZE = 2 # The delimiter is the character '|', of which there are two of them in the payload, each 1 byte.
    MAX_PAYLOAD_LENGTH = 1400 # 1400 bytes fills up frames, but not enough to cause fragmentation with a 1500-byte MTU.

    # Variables that are changed per-frame sent.
    sequenceNumber = 0 # Starting sequence number for packet ordering.
    payloadPadding = 0 # Used to determine the number of bytes of padding to get to MAX_PAYLOAD_LENGTH.
    complete = False if numberOfFramesToSend is not None else True  # Once all numberOfFramesToSend frames are sent, the sending process is complete.

    # Continue to send frames until numberOfFramesToSend is reached.
    while(not complete):
        try:
            sequenceNumber += 1

            # Determine how much (if any) padding is needed for a given frame before it is sent.
            frameLength = len(str(sequenceNumber) + srcPhysicalAddr) + len(PDUToSend) + PAYLOAD_DELIMITER_SIZE
            if(frameLength < MAX_PAYLOAD_LENGTH):
                payloadPadding = MAX_PAYLOAD_LENGTH - frameLength
            else:
                payloadPadding = 0

            # Add the test protocol header encapsulated in the ICMP message.
            frameWithCustomPayload = PDUToSend/Raw(load = "{0}|{1}|{2}".format(srcPhysicalAddr, sequenceNumber, 'A' * payloadPadding))
            
            # Send frame.
            sendp(frameWithCustomPayload, iface=port, count = 1, verbose = False)

            sys.stdout.write(f"\rSent {sequenceNumber} frames")
            sys.stdout.flush()

            # Determine if sending has completed.
            if(sequenceNumber == numberOfFramesToSend):
                complete = True
                print("\nFinished\n")

            # Add a delay to sending the next frame if needed.
            if(delay is not None):
                time.sleep(delay)

        # If the user kills the sending process via a CTRL+C (or a different method), stop sending.
        except KeyboardInterrupt:
            complete = True
            print("\nFinished\n")

    return None

def recvTraffic(port, captureFilePath):
    global frameCounter

    srcPhysicalAddr = get_if_hwaddr(port)

    filterToUse = "ether src not {} and {}" # example full cmd: tcpdump -i eth1 ether src not 02:de:3a:3f:a2:fd and icmp
    commandToUse = 'sudo tshark -i {} -w {} -F libpcap {}'

    try:
        filterForEIBPTraffic = '"icmp[0] == 1"'
        filterToUse = filterToUse.format(srcPhysicalAddr, filterForEIBPTraffic)
        commandToUse = commandToUse.format(port, captureFilePath, filterToUse)
        call(commandToUse, shell=True)

    except KeyboardInterrupt:
        print("\nExited program")

    return None

def analyzeTraffic(capture):
    frameCounter = {}

    capture = rdpcap(capture)

    for frame in capture:
        if(frame[ICMP].type == 1):
            payload = frame[Raw].load

        else:
            sys.exit("Can't find a payload")

        payload = str(payload, 'utf-8')
        payloadContent = payload.split("|")
        source = payloadContent[0]
        newSeqNum = int(payloadContent[1])

        if source not in frameCounter:
            # Updated Sequence Number, List of missed frames, Total number of frames sent, list of out of order frames, lost of duplicate frames
            frameCounter[source] = [newSeqNum, [], 1, [], []]

        else:
            currentSeqNum = frameCounter[source][0]          # The current sequence number for the source address
            expectedNextSeqNum = frameCounter[source][0] + 1 # The next expected sequence number for the source address

            if(currentSeqNum == newSeqNum and newSeqNum == 1):
                continue

            if(newSeqNum in frameCounter[source][1]):
                frameCounter[source][1].remove(newSeqNum)
                frameCounter[source][3].append(newSeqNum)
                frameCounter[source][2] += 1
                continue

            if(newSeqNum not in frameCounter[source][1] and (newSeqNum < currentSeqNum or newSeqNum == currentSeqNum)): # NEW STUF TO LOOK FOR DUPLICATES
                frameCounter[source][4].append(newSeqNum)
                frameCounter[source][2] += 1
                continue

            missedFrames = newSeqNum - expectedNextSeqNum # get frames 1-5, get frame 10, missing 6-9

            while(missedFrames != 0):
                missingSeqNum = currentSeqNum + missedFrames
                frameCounter[source][1].append(missingSeqNum)
                missedFrames -= 1

            frameCounter[source][0] = newSeqNum # Update the current sequence number
            frameCounter[source][2] += 1        # Update how many frames we have received from this source in total

    f = open("trafficResult.txt", "w+")
    for source in frameCounter:
        endStatement = "{0} frames lost from source {1} {2} | {3} received | {4} Not sequential {5} | {6} duplicates {7}\n"
        outputMissingFrames = ""
        outputUnorderedFrames = ""
        outputDuplicateFrames = ""

        if(frameCounter[source][1]):
            frameCounter[source][1].sort()
            outputMissingFrames = frameCounter[source][1]

        if(frameCounter[source][3]):
            frameCounter[source][3].sort()
            outputUnorderedFrames = frameCounter[source][3]

        if(frameCounter[source][4]):
            frameCounter[source][4].sort()
            outputDuplicateFrames = frameCounter[source][4]

        f.write(endStatement.format(len(frameCounter[source][1]), source, outputMissingFrames, frameCounter[source][2], len(frameCounter[source][3]), outputUnorderedFrames, len(frameCounter[source][4]), outputDuplicateFrames))

    f.close()

    return None

# Start of the program
if __name__ == "__main__":
    main()