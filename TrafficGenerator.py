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
from pathlib import Path
import time
import argparse
import sys
import os

frameCounter = {}  # Global dictionary to hold frame/packet payload content for analysis on the receiving end


def scriptDir():
    """Directory containing this script (not the current working directory)."""
    return Path(__file__).resolve().parent


def defaultPcapPath():
    """Default capture path when -r/--receive is used without a filename."""
    return Path("/tmp") / "results.pcap"


def ensureCaptureFile(path_str: str):
    """
    Ensure the capture file exists and is chmod 777.
    Also tries to chown back to the invoking sudo user if possible.
    Returns an absolute path string for tshark.
    """
    p = Path(path_str).expanduser()

    # If relative, make it relative to current working directory
    # (Path does this naturally; we just resolve to absolute for tshark).
    p_parent = p.parent
    if p_parent and not p_parent.exists():
        p_parent.mkdir(parents=True, exist_ok=True)

    # Touch file
    try:
        p.touch(exist_ok=True)
    except Exception as e:
        sys.exit(f"Failed to create capture file '{p}': {e}")

    # chmod 777
    try:
        os.chmod(p, 0o777)
    except Exception as e:
        sys.exit(f"Failed to chmod 777 on '{p}': {e}")

    # If running via sudo, try to set ownership back to original user
    # so downloads/cleanup are nicer.
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            import pwd
            import grp
            uid = pwd.getpwnam(sudo_user).pw_uid
            gid = grp.getgrnam(sudo_user).gr_gid
            os.chown(p, uid, gid)
        except Exception:
            # Non-fatal; permissions are already wide open
            pass

    return str(p.resolve())


def main():
    # ArgumentParser object to read in command line arguments
    argParser = argparse.ArgumentParser(description="Basic traffic generator for protocol reconvergence testing purposes")

    # Sender arguments.
    argParser.add_argument("-s", "--send")  # Destination (receiver) node
    argParser.add_argument("-c", "--count", type=int)  # The number of frames to send.
    argParser.add_argument("-d", "--delay", type=float)  # Add a delay when sending traffic.

    # Receiver arguments.
    # If "-r" is provided without a filename, default to /tmp/results.pcap.
    argParser.add_argument(
        "-r", "--receive",
        nargs="?",
        const="__DEFAULT_PCAP__",
        default=None,
        help="Receive traffic and write to a pcap file (default: /tmp/results.pcap)"
    )

    # Analyze traffic.
    argParser.add_argument("-a", "--analyze")  # argument of capture needed

    # Shared arguments.
    argParser.add_argument("-e", "--port", default="eth1")  # By default, it's eth1 on our testbeds.

    # Parse the arguments.
    args = argParser.parse_args()
    port = args.port

    # Receive traffic.
    if args.receive is not None:
        if args.receive == "__DEFAULT_PCAP__":
            capture_arg = str(defaultPcapPath())
        else:
            capture_arg = args.receive

        capture_path = ensureCaptureFile(capture_arg)
        recvTraffic(port, capture_path)

    # Send traffic.
    elif args.send:
        dstLogicalAddr = args.send
        count = args.count
        delay = args.delay
        sendTraffic(dstLogicalAddr, count, delay, port)

    # Analyze traffic.
    elif args.analyze:
        captureFile = args.analyze
        print(f"Working on capture file {captureFile}...")
        analyzeTraffic(captureFile)

    else:
        sys.exit("Syntax error: incorrect arguments (use -h for help)")  # Error out if the arguments are bad or missing.

    return None


def sendTraffic(dstLogicalAddr, count, delay, port):
    # Information needed to generate a custom payload and build protocol headers.
    srcPhysicalAddr = get_if_hwaddr(port)

    # Added UDP at the end to maybe calm this down a bit.
    PDUToSend = Ether(src=srcPhysicalAddr) / IP(dst=dstLogicalAddr) / ICMP(type=1)
    generateContinousTraffic(PDUToSend, count, srcPhysicalAddr, delay, port)

    return None


def generateContinousTraffic(PDUToSend, numberOfFramesToSend, srcPhysicalAddr, delay, port):
    # Constants.
    PAYLOAD_DELIMITER_SIZE = 2  # The delimiter is the character '|', of which there are two of them in the payload, each 1 byte.
    MAX_PAYLOAD_LENGTH = 1400   # 1400 bytes fills up frames, but not enough to cause fragmentation with a 1500-byte MTU.

    # Variables that are changed per-frame sent.
    sequenceNumber = 0
    payloadPadding = 0
    complete = False if numberOfFramesToSend is not None else True

    # Continue to send frames until numberOfFramesToSend is reached.
    while not complete:
        try:
            sequenceNumber += 1

            # Determine how much (if any) padding is needed for a given frame before it is sent.
            frameLength = len(str(sequenceNumber) + srcPhysicalAddr) + len(PDUToSend) + PAYLOAD_DELIMITER_SIZE
            if frameLength < MAX_PAYLOAD_LENGTH:
                payloadPadding = MAX_PAYLOAD_LENGTH - frameLength
            else:
                payloadPadding = 0

            # Add the test protocol header encapsulated in the ICMP message.
            frameWithCustomPayload = PDUToSend / Raw(
                load="{0}|{1}|{2}".format(srcPhysicalAddr, sequenceNumber, 'A' * payloadPadding)
            )

            # Send frame.
            sendp(frameWithCustomPayload, iface=port, count=1, verbose=False)

            sys.stdout.write(f"Sent {sequenceNumber} frames")
            sys.stdout.flush()

            # Determine if sending has completed.
            if sequenceNumber == numberOfFramesToSend:
                complete = True
                print("Finished")

            # Add a delay to sending the next frame if needed.
            if delay is not None:
                time.sleep(delay)

        except KeyboardInterrupt:
            complete = True
            print("Finished")

    return None


def recvTraffic(port, captureFilePath):
    srcPhysicalAddr = get_if_hwaddr(port)

    # Capture filter (BPF): exclude our own source MAC and only match ICMP type 1
    # NOTE: "icmp[0] == 1" refers to ICMP type in the ICMP header.
    capture_filter = f"ether src not {srcPhysicalAddr} and icmp[0] == 1"

    # Avoid shell quoting issues by using argv form.
    command = [
        "sudo", "tshark",
        "-i", str(port),
        "-w", str(captureFilePath),
        "-F", "libpcap",
        capture_filter,
    ]

    try:
        call(command)

    except KeyboardInterrupt:
        print("Exited program")

    return None


def analyzeTraffic(capturePath):
    frameCounter = {}

    capture = rdpcap(capturePath)

    for frame in capture:
        if frame.haslayer(ICMP) and frame[ICMP].type == 1:
            if not frame.haslayer(Raw):
                continue
            payload = frame[Raw].load
        else:
            continue

        payload = str(payload, 'utf-8')
        payloadContent = payload.split("|")
        source = payloadContent[0]
        newSeqNum = int(payloadContent[1])

        if source not in frameCounter:
            frameCounter[source] = [newSeqNum, [], 1, [], []]
        else:
            currentSeqNum = frameCounter[source][0]
            expectedNextSeqNum = frameCounter[source][0] + 1

            if currentSeqNum == newSeqNum and newSeqNum == 1:
                continue

            if newSeqNum in frameCounter[source][1]:
                frameCounter[source][1].remove(newSeqNum)
                frameCounter[source][3].append(newSeqNum)
                frameCounter[source][2] += 1
                continue

            if newSeqNum not in frameCounter[source][1] and (newSeqNum < currentSeqNum or newSeqNum == currentSeqNum):
                frameCounter[source][4].append(newSeqNum)
                frameCounter[source][2] += 1
                continue

            missedFrames = newSeqNum - expectedNextSeqNum

            while missedFrames != 0:
                missingSeqNum = currentSeqNum + missedFrames
                frameCounter[source][1].append(missingSeqNum)
                missedFrames -= 1

            frameCounter[source][0] = newSeqNum
            frameCounter[source][2] += 1

    # Write the results file to the same directory as the python script.
    pcap_path = Path(capturePath).expanduser().resolve()
    pcap_stem = pcap_path.stem

    out_dir = scriptDir()
    out_dir.mkdir(parents=True, exist_ok=True)

    resultFile = out_dir / f"{pcap_stem}_result.txt"
    f = open(resultFile, "w+")

    for source in frameCounter:
        endStatement = "{0} frames lost from source {1} {2} | {3} received | {4} Not sequential {5} | {6} duplicates {7}"

        outputMissingFrames = ""
        outputUnorderedFrames = ""
        outputDuplicateFrames = ""

        if frameCounter[source][1]:
            frameCounter[source][1].sort()
            outputMissingFrames = frameCounter[source][1]

        if frameCounter[source][3]:
            frameCounter[source][3].sort()
            outputUnorderedFrames = frameCounter[source][3]

        if frameCounter[source][4]:
            frameCounter[source][4].sort()
            outputDuplicateFrames = frameCounter[source][4]

        f.write(endStatement.format(
            len(frameCounter[source][1]),
            source,
            outputMissingFrames,
            frameCounter[source][2],
            len(frameCounter[source][3]),
            outputUnorderedFrames,
            len(frameCounter[source][4]),
            outputDuplicateFrames
        ))

    f.close()
    print(f"Wrote results to: {resultFile}")
    return None


if __name__ == "__main__":
    main()
