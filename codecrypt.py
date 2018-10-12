# -*- coding: utf-8 -*-
"""
Python interface to exa's codecrypt post-quantum cryptographic application

codecrypt is available at https://gitea.blesmrt.net/exa/codecrypt or
https://e-x-a.org/codecrypt

This Python module written by Mike Ingle <inglem@pobox.com> or <mike@confidantmail.org>
I have also ported codecrypt to win32, and this module works in either
Unix or win32. Tested on python 2.7 and python 3.4

Limitations of codecrypt compared to gpg: you can only encrypt a message to one
recipient at a time, and you can only encrypt or sign a message small enough to
fit in memory. I have tested up to a few megabytes.

Codecrypt signature keys use up. Most are good for 65536 signatures. The
types (listed in ccr -g help) with H20C in the name are good for 1M
signatures. If you want a long-lasting key you need to use a master key to
sign secondary keys, and use the secondary keys to sign messages.

Do not copy a secret key and then use it in two places. Secret keys have a
nonce that gets incremented after every use, and reusing a nonce compromises
the security.

These operations call the codecrypt binary without a shell, start threads to
capture stdout and stderr, feed input to stdin if any, and block until
codecrypt exits.

In general a zero retcode means an operation worked, and a nonzero retcode
means it failed and you should look at stderr return string to find out why.
See codecrypt_testdemo.py for usage examples.

Codecrypt source and win32 binary is at https://github.com/mike805/codecrypt-win32

Check out my GPG-based email system Confidant Mail at https://www.confidantmail.org/
Confidant Mail is the only secure email system with multi-gigabyte attachment support.
"""

import logging
import sys
import os
import subprocess
import threading
import time
import re
import tempfile


re_pub_priv_key = re.compile("public key in keypair with algorithm (\S+), name `([^']+)'")
re_pub_key = re.compile("public key with algorithm (\S+), name `([^']+)'")
re_priv_key = re.compile("key pair with algorithm (\S+), name `([^']+)'")
re_keyid = re.compile("\s*fingerprint/keyid: ([0-9a-f:]+)")
re_sigs_remain = re.compile(".*notice: ([0-9]+) signatures remaining.*",re.DOTALL)
re_enc_sig_info = re.compile("^\s*([^:]+): (.*)$")
re_enc_sig_info_ticks = re.compile("^\s*([^:]+): `(.*)'$")

# Line reader also used in gpg driver
# thank you http://eyalarubas.com/python-subproc-nonblock.html
from threading import Thread
#from Queue import Queue, Empty
#class NonBlockingStreamReader:
#
#	def __init__(self, stream):
#		"""
#		stream: the stream to read from.
#				Usually a process' stdout or stderr.
#		"""
#		self._s = stream
#		self._q = Queue()
#
#		def _populateQueue(stream, queue):
#			"""
#			Collect lines from 'stream' and put them in 'queue'.
#			"""
#			while True:
#				line = stream.readline()
#				if line:
#					line = line.rstrip('\r\n')
#					queue.put(line)
#				else:
#					queue.put('## EOF ##')
#					break
#					#raise UnexpectedEndOfStream
#		self._t = Thread(target = _populateQueue,
#				args = (self._s, self._q))
#		self._t.daemon = True
#		self._t.start() #start collecting lines from the stream
#
#	def readline(self, timeout = None):
#		try:
#			return self._q.get(block = timeout is not None,
#					timeout = timeout)
#		except Empty:
#			return None
##class UnexpectedEndOfStream(Exception): pass

# Binary reader for crypto material
class NonBlockingBinaryStreamReader:

	def __init__(self, stream):
		"""
		stream: the stream to read from.
				Usually a process' stdout or stderr.
		"""
		self._s = stream
		self.buf = bytes()
		self.eof = False
		self._t = Thread(target = self._populateString, args = ())
		self._t.daemon = True
		self._t.start() #start collecting bytes from the stream

	def _populateString(self):
		"""
		Collect bytes from 'stream' and put them in 'queue'.
		"""
		while self.eof == False:
			chunk = self._s.read()
			if chunk:
				self.buf += chunk
			else:
				self.eof = True;
				#raise UnexpectedEndOfStream


################################################################################
class codecrypt:

	def __init__(self,ccr_path,ccr_datadir = None,debug = False):
		"""
		codecrypt object constructor
		ccr_path = full path to codecrypt executable like /usr/bin/ccr
		ccr_datadir = path for ccr to store keys (defaults to current dir on
			Windows if not specified)
		"""
		self.logger = logging.getLogger(__name__)
		self.ccr_path = ccr_path
		self.ccr_datadir = ccr_datadir
 		# Setting keyring password to None will cause codecrypt to stop and prompt, set to "" to avoid
		self.keyring_password = None
		self.debug = debug

	def set_keyring_password(self,keyring_password):
		"""
		Set password for encrypted private keys
		Note: setting to None (which is the default if not set) will cause
		codecrypt to prompt on the console if it tries to use an encrypted
		private key. If you want it to fail instead, set the password to ""
		"""
		self.keyring_password = keyring_password

	def ccr_operation(self,cmdline,data_in):
		"""
		Run a codecrypt command without a shell
		input command line as list, data for stdin or None
		output return code, stdout, stderr
		blocks until codecrypt completes
		"""
		if self.debug == True:
			cmdstr = str()
			for cmd in cmdline:
				if len(cmdstr) == 0:
					cmdstr += cmd
				else:
					cmdstr += ' ' + cmd
			self.logger.debug(cmdstr)
		try:
			subproc_env = dict(os.environ) # copy, do not edit own env
			if self.ccr_datadir != None:
				subproc_env['CCR_DIR'] = self.ccr_datadir
			if self.keyring_password != None:
				subproc_env['CCR_KEYRING_PASSWORD'] = self.keyring_password
			if sys.platform == 'win32':
				# http://stackoverflow.com/questions/7006238/how-do-i-hide-the-console-when-i-use-os-system-or-subprocess-call/7006424#7006424
				si = subprocess.STARTUPINFO()
				si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
				cmdh = subprocess.Popen(cmdline,bufsize=16384,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell = False,startupinfo = si,env = subproc_env)
			else:
				#cmdh = subprocess.Popen(cmdline,bufsize=16384,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell = False)
				cmdh = subprocess.Popen(cmdline,bufsize=16384,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell = False,env = subproc_env)
			errout = NonBlockingBinaryStreamReader(cmdh.stderr)
			output = NonBlockingBinaryStreamReader(cmdh.stdout)
			if (data_in) != None:
				cmdh.stdin.write(data_in)
			cmdh.stdin.close()
			retcode = cmdh.wait()
			while output.eof == False or errout.eof == False:
				time.sleep(0.1)
			cmdh.stdout.close()
			cmdh.stderr.close()
			return retcode,output.buf,errout.buf.decode('utf-8')
		except Exception as exc:
			self.logger.error("Failed to run codecrypt binary: %s",str(exc))
			return 9,"",str(exc)

	def ccr_version(self):
		"""
		Get codecrypt version and make sure binary can be called
		returns retcode, version string, err_out
		"""
		cmdline = [ self.ccr_path,'-V' ]
		retcode,data_out,err_out = self.ccr_operation(cmdline,None)
		if retcode != 0:
			return retcode,data_out,err_out
		line1 = None
		for line in data_out.decode('utf-8').split("\n"):
			line = line.replace("\r","")
			if line1 == None:
				line1 = line
		return retcode,line1,err_out

	def list_keys_common(self,cmdline,data_in = None):
		"""
		Internal parsing function for list_keys and list_import_keys
		"""
		keys = [ ]
		retcode,data_out,err_out = self.ccr_operation(cmdline,data_in)
		if retcode != 0:
			return retcode,err_out,keys
		key_priv = None
		key_name = None
		key_alg = None
		key_hash = None
		for line in data_out.decode('utf-8').split("\n"):
			line = line.replace("\r","")
			m = re_pub_priv_key.match(line)
			if m:
				key_priv = True
				key_alg = m.group(1)
				key_name = m.group(2)
			else:
				m = re_pub_key.match(line)
				if m:
					key_priv = False
					key_alg = m.group(1)
					key_name = m.group(2)
				else:
					m = re_priv_key.match(line)
					if m:
						key_priv = True
						key_alg = m.group(1)
						key_name = m.group(2)
					else:	
						m = re_keyid.match(line)
						if m:
							key_hash = '@' + m.group(1).replace(':','')
							if key_name != None:
								keys.append((key_hash,key_alg,key_name,key_priv))
								key_name = None
		return retcode,err_out,keys

	def list_keys(self):
		"""
		Lists keys, returns retcode,stderr out,list of tuples where each tuple is:
			key hash,key_alg,key_name,key_priv
			key_hash = hex hash with leading @ can be passed to other methods
			key_alg = type of key
			key_name = username assigned to key
			key_priv = True/False do we have the private key?
		"""
		cmdline = [ self.ccr_path,'-k','-f' ]
		return self.list_keys_common(cmdline,None)

	def list_import_keys(self,keys_in,ascii_armor = False,secret_key = False):
		"""
		Lists the contents of one or more exported keys, in the same format as list_keys above
		"""
		if secret_key == True:
			cmdline = [ self.ccr_path,'-I','-n' ]
		else:
			cmdline = [ self.ccr_path,'-i','-n' ]
		if ascii_armor == True:
			cmdline.append('-a')
		cmdline.append('-f')
		return self.list_keys_common(cmdline,keys_in)
		
	def import_keys(self,keys_in,confirm = True,ascii_armor = False,secret_key = False):
		"""
		import keys into keyring, specify ascii armor and secret/public
		returns retcode,stdout (usually blank), stderr
		"""
		if secret_key == True:
			cmdline = [ self.ccr_path,'-I' ]
		else:
			cmdline = [ self.ccr_path,'-i' ]
		if ascii_armor == True:
			cmdline.append('-a')
		if confirm == True:
			cmdline.append('-y')
		retcode,data_out,err_out = self.ccr_operation(cmdline,keys_in)
		return retcode,data_out,err_out
		
	def export_key(self,keyid,ascii_armor = False,secret_key = False):
		"""
		export key from keyring, specify keyid as name, or hex hash returned from list_keys
		exports a public key unless secret_key set to true
		"""
		if secret_key == True:
			cmdline = [ self.ccr_path,'-P','-y','-F',keyid ]
		else:
			cmdline = [ self.ccr_path,'-p','-F',keyid ]
		if ascii_armor == True:
			cmdline.append('-a')
		retcode,data_out,err_out = self.ccr_operation(cmdline,None)
		return retcode,data_out,err_out
		
	def delete_key(self,keyid,confirm = True,secret_key = False):
		"""
		delete a public or secret key from keyring
		codecrypt returns 0 even if this fails, so non-null err_out is a failure
		"""
		if secret_key == True:
			cmdline = [ self.ccr_path,'-X',keyid ]
		else:
			cmdline = [ self.ccr_path,'-x',keyid ]
		if confirm == True:
			cmdline.append('-y')
		retcode,data_out,err_out = self.ccr_operation(cmdline,None)
		if err_out != '':
			retcode = 1
		return retcode,data_out,err_out

	def rename_key(self,keyid,new_name,confirm = True,secret_key = False):
		"""
		delete a public or secret key from keyring
		codecrypt returns 0 even if this fails, so non-null err_out is a failure
		"""
		if secret_key == True:
			cmdline = [ self.ccr_path,'-M',keyid,'-N',new_name ]
		else:
			cmdline = [ self.ccr_path,'-m',keyid,'-N',new_name ]
		if confirm == True:
			cmdline.append('-y')
		retcode,data_out,err_out = self.ccr_operation(cmdline,None)
		if err_out != '':
			retcode = 1
		return retcode,data_out,err_out

	def lock_key(self,keyid):
		"""
		Lock a key with a password set via set_keyring_password
		"""
		cmdline = [ self.ccr_path,'-L','-F',keyid,'-y' ]
		retcode,data_out,err_out = self.ccr_operation(cmdline,None)
		if "key locking failed" in err_out:
			retcode = 1 # codecrypt returns 0 even if it fails
		return retcode,data_out,err_out

	def unlock_key(self,keyid):
		"""
		Unlock a key with a password set via set_keyring_password
		"""
		cmdline = [ self.ccr_path,'-U','-F',keyid,'-y' ]
		retcode,data_out,err_out = self.ccr_operation(cmdline,None)
		if "key unlocking failed" in err_out:
			retcode = 1 # codecrypt returns 0 even if it fails
		return retcode,data_out,err_out
	
	def find_new_key(self,old_keylist,new_keylist):
		"""
		internal function to find the new key after a generate key operation
		"""
		existing_hashes = dict()
		for keyline in old_keylist:
			key_hash,key_alg,key_name,key_priv = keyline
			existing_hashes[key_hash] = 1;	
		for keyline in new_keylist:
			key_hash,key_alg,key_name,key_priv = keyline
			if key_hash not in existing_hashes:
				return keyline
		return None
		
	def generate_key(self,key_name,algorithm):
		"""
		generate a signature or encryption key pair (algorithm string decides which)
		returns retcode, stdout, stderr, and the new key as a tuple in list_keys format

		This function usually takes minutes to complete, and it blocks until finished!
		If your program is interactive, you need to run this in a thread. If you want
		to keep doing codecrypt operations while you wait, you need to create the new
		key in a temporary keyring (separate codecrypt object) and then export it from
		the temporary keyring and import it into the main keyring.
		"""
		retcode,err_out,old_keylist = self.list_keys()
		if retcode != 0:
			return retcode,None,err_out,None
		cmdline = [ self.ccr_path,'-g',algorithm,'-N',key_name ]
		retcode,data_out,err_out = self.ccr_operation(cmdline,None)
		retcode2,err2_out,new_keylist = self.list_keys()
		new_key = self.find_new_key(old_keylist,new_keylist)
		return retcode,data_out,err_out,new_key
		
	def generate_signature(self,keyid,data_in,ascii_armor = False,cleartext_mode = False):
		"""
		generates a signed data object, specify keyid, data (binary is ok),
		ascii_armor the output True/False, cleartext mode True/False
		returns retcode, data_out, err_out, signatures remaining for this key

		This is a signed data object: the data_out contains the entire input string
		wrapped in a signature. Cleartext mode expects text input.
		"""
		sigs_remaining = -1
		cmdline = [ self.ccr_path,'-s','-u',keyid ]
		if cleartext_mode == True:
			cmdline.append('-C')
		elif ascii_armor == True:
			cmdline.append('-a')
		retcode,data_out,err_out = self.ccr_operation(cmdline,data_in)
		m = re_sigs_remain.match(err_out)
		if m:
			sigs_remaining = int(m.group(1))	
		return retcode,data_out,err_out,sigs_remaining

	def generate_detached_signature(self,keyid,data_in,ascii_armor = False):
		"""
		generates a detached signature object, specify keyid, data (binary is ok),
		ascii armor the output True/False. Returns retcode, data_out is the detached
		signature, stderr out, signatures remaining for this key.
		Note that the data_out is not the actual stdout of the process, but is the
		detached signature retrieved from a temporary file.
		"""
		os_fd,filepath = tempfile.mkstemp(prefix = 'tmp.ccr.')
		os.close(os_fd)
		sigs_remaining = -1
		cmdline = [ self.ccr_path,'-s','-u',keyid,'-b',filepath ]
		if ascii_armor == True:
			cmdline.append('-a')
		retcode,data_out,err_out = self.ccr_operation(cmdline,data_in)
		fh = open(filepath,'rb')
		data_out = fh.read()
		fh.close()	
		os.unlink(filepath)
		m = re_sigs_remain.match(err_out)
		if m:
			sigs_remaining = int(m.group(1))	
		return retcode,data_out,err_out,sigs_remaining

	def parse_enc_sig_details(self,details_in):
		"""
		internal function to parse signature details
		"""
		prefix = ''
		details = dict()
		details_type = str(type(details_in)) # this approach works in python 2.7 and 3.4
		if 'str' not in details_type and 'unicode' not in details_type:
			return details
		for line in details_in.split("\n"):
			line = line.replace("\r","")
			if line == 'incoming encrypted message details:':
				prefix = 'encryption '
			elif line == 'incoming signed message details:':
				prefix = 'signature '
			else:
				m = re_enc_sig_info_ticks.match(line)
				if m == None:
					m = re_enc_sig_info.match(line)
				if m:
					linename = m.group(1)
					if linename == 'algorithm':
						linename = prefix + linename
					details[linename] = m.group(2)
		return details
		
	def verify_signature(self,data_in,ascii_armor = False,cleartext_mode = False):
		"""
		Verify a signed data object and get the plaintext
		Returns retcode, data, err_out, signature good T/F, and parsed details as list
		"""
		signature_good = False
		cmdline = [ self.ccr_path,'-v' ]
		if cleartext_mode == True:
			cmdline.append('-C')
		elif ascii_armor == True:
			cmdline.append('-a')
		retcode,data_out,err_out = self.ccr_operation(cmdline,data_in)
		details = self.parse_enc_sig_details(err_out)
		if retcode == 0 and 'verification status' in details and details['verification status'] == 'GOOD signature ;-)':
			signature_good = True
		return retcode,data_out,err_out,signature_good,details

	def verify_detached_signature(self,data_in,signature_in,ascii_armor = False):
		"""
		Verify a detached signature object against the data
		Returns retcode, data, err_out, signature good T/F, and parsed details as list
		"""
		signature_good = False
		os_fd,filepath = tempfile.mkstemp(prefix = 'tmp.ccr.')
		os.write(os_fd,signature_in)
		os.close(os_fd)
		cmdline = [ self.ccr_path,'-v' ]
		if ascii_armor == True:
			cmdline.append('-a')
		cmdline.extend(['-b',filepath])
		retcode,data_out,err_out = self.ccr_operation(cmdline,data_in)
		os.unlink(filepath)
		details = self.parse_enc_sig_details(err_out)
		if retcode == 0 and 'verification status' in details and details['verification status'] == 'GOOD signature ;-)':
			signature_good = True
		return retcode,data_out,err_out,signature_good,details
		
	def encrypt(self,keyid,data_in,ascii_armor = False):
		"""
		Encrypt a message with a public key
		"""
		cmdline = [ self.ccr_path,'-e','-r',keyid ]
		if ascii_armor == True:
			cmdline.append('-a')
		retcode,data_out,err_out = self.ccr_operation(cmdline,data_in)
		return retcode,data_out,err_out
		
	def decrypt(self,data_in,ascii_armor = False):
		"""
		Decrypt a public-key encrypted message
		Returns retcode, plaintext, err_out, and parsed details list
		"""
		cmdline = [ self.ccr_path,'-d' ]
		if ascii_armor == True:
			cmdline.append('-a')
		retcode,data_out,err_out = self.ccr_operation(cmdline,data_in)
		details = self.parse_enc_sig_details(err_out)
		return retcode,data_out,err_out,details
		
	def encrypt_sign(self,sig_keyid,enc_keyid,data_in,ascii_armor = False):
		"""
		Sign and encrypt a message, combines above two operations
		Specify secret key for signature and public key for encryption 
		"""
		sigs_remaining = -1
		cmdline = [ self.ccr_path,'-e','-s','-u',sig_keyid,'-r',enc_keyid ]
		if ascii_armor == True:
			cmdline.append('-a')
		retcode,data_out,err_out = self.ccr_operation(cmdline,data_in)
		m = re_sigs_remain.match(err_out)
		if m:
			sigs_remaining = int(m.group(1))	
		return retcode,data_out,err_out,sigs_remaining
		
	def decrypt_verify(self,data_in,ascii_armor = False):
		"""
		Decrypt and verify signature on a message
		Returns retcode, plaintext, err_out, and parsed details list
		"""
		signature_good = False
		cmdline = [ self.ccr_path,'-d','-v' ]
		if ascii_armor == True:
			cmdline.append('-a')
		retcode,data_out,err_out = self.ccr_operation(cmdline,data_in)
		details = self.parse_enc_sig_details(err_out)
		if retcode == 0 and 'verification status' in details and details['verification status'] == 'GOOD signature ;-)':
			signature_good = True
		return retcode,data_out,err_out,signature_good,details
		
			
# EOF
