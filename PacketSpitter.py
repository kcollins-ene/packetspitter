#!/usr/bin/env python
# encoding: utf-8
'''
Packet Spitter -- Simple Payload Packet Spitter

Spit Packets with an ASCII UTC TimeStamp and CR

@author:     Kevin Collins <kcollins@enengineering.com>

@copyright:  2017 EN Engineering, LLC. All rights reserved.

@license:    Apache License 2.0

@contact:    kcollins@enengineering.com
@deffield:   updated: Updated
'''

import sys
import time
import os
import socket
import logging
import binascii
from threading import Event, Thread
from optparse import OptionParser

__all__ = []
__version__ = '1.0.9'
__date__ = '2017-03-23'
__updated__ = '2017-03-23'

DEBUG = 0
TESTRUN = 0
PROFILE = 0

logger = logging.getLogger(__name__)

# helper stuff
current_ms_time = lambda: int(round(time.time() * 1000))

# main routine
def main(argv=None):
	"""Command line options.

	Parameters:
		argv : incoming command line arguments
	"""

	program_name = os.path.basename(sys.argv[0])
	program_version = "v{0}".format(__version__)
	program_build_date = "%s" % __updated__

	program_version_string = '%%prog %s (%s)' % (program_version, program_build_date)
	program_longdesc = '''Spits ASCII TimeStamp Packets at a defined interval'''
	program_license = "Copyright 2017 Kevin Collins (EN Engineering, LLC)                                            \
				Licensed under the Apache License 2.0\nhttp://www.apache.org/licenses/LICENSE-2.0"

	if argv is None:
		argv = sys.argv[1:]

	try:
		# setup option parser
		parser = OptionParser(version=program_version_string, epilog=program_longdesc, description=program_license,
		                      conflict_handler="resolve")
		parser.add_option("-v", "--verbose", dest="verbose", action="count",
		                  help="set verbosity level [default: %default]")
		parser.add_option("-r", "--rate", dest="rate", help="poll rate for Packet Spitting in milliseconds (ms)",
		                  type="int")
		parser.add_option("-p", "--port", dest="port", help="listening port for Packet Spitter (TCP)",
		                  type="int")

		# set defaults
		parser.set_defaults(verbose=1)
		parser.set_defaults(rate=100)
		parser.set_defaults(port=8901)

		# process options
		(opts, args) = parser.parse_args(argv)

		if opts.verbose > 0:
			print("verbosity level = %i" % opts.verbose)
			logging.basicConfig(format='%(asctime)s %(levelname)s:%(module)s: %(message)s', level=logging.DEBUG)
		else:
			logging.basicConfig(format='%(asctime)s %(levelname)s:%(module)s: %(message)s', level=logging.INFO)

		if opts.rate:
			print("packet spitting rate = %i" % opts.rate)
		if opts.port:
			print("listening port = %i" % opts.port)

		# main body
		try:
			# create a socket connection
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

			# bind the socket to the host and port
			try:
				s.bind(('', opts.port))
			except socket.error as msg:
				logger.error("Bind Failed. Error code: {0} Message: {1}".format(msg[0], msg[1]))
				return

			# Thread Event Messager
			runSignal = Event()
			runSignal.set()
			c = None

			# Start Listening on Socket
			s.listen(8)

			# Begin client communication
			while 1:
				# accept the connection
				conn, addr = s.accept()
				logger.debug("Client Connected from {0}:{1}, forking...".format(addr[0], addr[1]))

				# start new client thread
				c = Thread(target=packetSpitter, args=(conn, runSignal))
				c.start()

				time.sleep(1)

			s.close()
		except KeyboardInterrupt as exc:
			print "Cancel Request, Ending..."
		finally:
			if c is not None and c.is_alive():
				runSignal.clear()
				runSignal.wait()
				c.join()
				s.close()

	except Exception, e:
		indent = len(program_name) * " "
		sys.stderr.write(program_name + ": " + repr(e) + "\n")
		sys.stderr.write(indent + "  for help use --help")
		return 2

def packetSpitter(conn, runSignal):
	# Gather host/port information
	host, port = conn.getpeername()
	lastTime = current_ms_time()
	count = 1

	# Begin Spitting Packets!
	while 1:
		# Check Event Signal
		if not runSignal.isSet():
			break

		currentTime = current_ms_time()
		if currentTime - lastTime >= 100:
			try:
				conn.sendall(spitPacket(currentTime))
			except:
				logger.debug("Error during write.")
				break
			lastTime = currentTime
			count += 1

		# Scan at 1ms
		time.sleep(0.001)


	# loop ended, close connection
	logger.info("Closing connection for " + host + ":" + str(port))
	conn.close()

	# Set event signal
	runSignal.set()


def spitPacket(timestamp):
	data = str(timestamp).zfill(19)
	logger.info("Spat Packet: %s" % data)
	data = data + "\r"
	logger.debug("Packet Contents: 0x" + binascii.hexlify(data))
	return data


if __name__ == "__main__":
	if DEBUG:
		sys.argv.append("-h")
	if TESTRUN:
		import doctest
		doctest.testmod()
	if PROFILE:
		import cProfile
		import pstats
		profile_filename = 'Test_profile.txt'
		cProfile.run('main()', profile_filename)
		statsfile = open("profile_stats.txt", "wb")
		p = pstats.Stats(profile_filename, stream=statsfile)
		stats = p.strip_dirs().sort_stats('cumulative')
		stats.print_stats()
		statsfile.close()
		sys.exit(0)
	sys.exit(main())