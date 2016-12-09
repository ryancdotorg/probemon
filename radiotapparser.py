import struct

# implemented as a class mostly for scoping
class RadioTapParser(object):
	def __init__(self):
		self.present = None
		self.data = None
		self.pkt = None
		self.pos = None

	def _get_field(self, bit, align, name, fmt):
		if self.present & 1<<bit:
			size = struct.calcsize(fmt)
			pad = self.pos % align
			# do alignment
			if pad:
				self.pos += align - pad

			tmp = struct.unpack(fmt, self.pkt[self.pos:self.pos+size])
			if len(tmp) == 1:
				tmp = tmp[0]

			self.data[name] = tmp
			self.pos += size

	def __call__(self, pkt):
		self.pkt = pkt
		ver, pad, length, present = struct.unpack('<BBHL', pkt[0:8])
		tmp = self.present = present
		self.pos = 8

		# this sucks
		while tmp & 1<<31:
			tmp = struct.unpack('<L', pkt[self.pos:self.pos+4])[0]
			self.pos += 4
			self.present += tmp << ((self.pos - 8) * 8)

		self.data = {'len': length}

		self._get_field( 0, 8, 'tsft', '<Q')
		self._get_field( 1, 1, 'flags', '<B')
		self._get_field( 2, 1, 'rate', '<B')
		self._get_field( 3, 2, 'freq', '<HH')
		self._get_field( 4, 1, 'fhss', '<BB')
		self._get_field( 5, 1, 'signal', '<b')
		self._get_field( 6, 1, 'noise', '<b')
		# don't care about these for now
		"""
		self._get_field( 7, 2, 'lockq', '<H')
		self._get_field( 8, 2, 'txatten', '<H')
		self._get_field( 9, 2, 'dbtxatten', '<H')
		self._get_field(10, 1, 'txpower, '<b')
		self._get_field(11, 1, 'ant, '<B')
		self._get_field(12, 1, 'dbantsignal, '<B')
		self._get_field(13, 1, 'dbantnoise, '<B')
		self._get_field(14, 2, 'rxflags, '<H')
		"""

		ret = self.data

		self.present = None
		self.data = None
		self.pkt = None
		self.pos = None

		return ret
