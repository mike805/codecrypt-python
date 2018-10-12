# -*- coding: utf-8 -*-

"""
Test/demo for codecrypt.py

This verifies that codecrypt and the python module are functional, and is
also a working example of how to use the python module. It creates two user
keyrings, generates key pairs in both, exchanges public keys between the
keyrings, and then sends some signed and encrypted messages back and forth.

Process exits with 0 on success, nonzero on failure

codecrypt is available at https://gitea.blesmrt.net/exa/codecrypt or
https://e-x-a.org/codecrypt

This Python module written by Mike Ingle <inglem@pobox.com> or <mike@confidantmail.org>
I have also ported codecrypt to win32, and this module works in either
Unix or win32. Tested on python 2.7 and python 3.4

Codecrypt source and win32 binary is at https://github.com/mike805/codecrypt-win32

Check out my GPG-based email system Confidant Mail at https://www.confidantmail.org/
Confidant Mail is the only secure email system with multi-gigabyte attachment support.
"""

import logging
import sys
from codecrypt import codecrypt

logging.basicConfig(level=logging.DEBUG,
	format="%(asctime)s %(levelname)-5s %(name)-10s %(threadName)-10s %(message)s")

# Location of ccr binary
if len(sys.argv) >= 2:
	ccr_binary = sys.argv[1]
elif sys.platform == 'win32':
	ccr_binary = 'ccr.exe'
else:
	ccr_binary = 'ccr'

lock_password = "OinkoInK"
error_count = 0
logger = logging.getLogger(__name__)
logger.debug("Create codecrypt object for Alice")
alice_ccr = codecrypt(ccr_binary,'./alice_keys', debug = True)
alice_ccr.set_keyring_password('')
logger.debug("Get version and check binary")
retcode,data_out,err_out = alice_ccr.ccr_version()
if retcode != 0:
	logger.error("Failed with code %i stderr %s",retcode,err_out);
	logger.error("Either put the codecrypt binary in your PATH, or enter it on the codecrypt_testdemo.py command line")
	error_count += 1
	sys.exit(1)
else:
	logger.debug("Succeeded, %s",data_out)

logger.debug("Get existing key list for Alice")
retcode,err_out,alice_keys = alice_ccr.list_keys()
if retcode != 0:
	logger.error("Failed with code %i stderr %s",retcode,err_out)
	error_count += 1
	sys.exit(1)
alice_sig_key = None
alice_enc_key = None
for thiskey in alice_keys:
	key_hash,key_alg,key_name,key_priv = thiskey
	logger.debug("key_name=%s,key_alg=%s,key_priv=%s",key_name,key_alg,key_priv)
	if key_name == 'Alice-sign':
		alice_sig_key = key_hash
	elif key_name == 'Alice-enc':
		alice_enc_key = key_hash

if alice_sig_key == None:
	logger.debug("Alice does not have a signature key, creating it will take a few minutes")
	retcode,data_out,err_out,thiskey = alice_ccr.generate_key('Alice-sign','SIG')
	if retcode != 0:
		logger.error("Failed with code %i stderr %s",retcode,err_out)
		error_count += 1
		sys.exit(1)
	else:
		logger.debug("Succeeded with code %i stderr %s",retcode,err_out)
	key_hash,key_alg,key_name,key_priv = thiskey
	alice_sig_key = key_hash
		
if alice_enc_key == None:
	logger.debug("Alice does not have an encryption key, creating it")
	retcode,data_out,err_out,thiskey = alice_ccr.generate_key('Alice-enc','ENC')
	if retcode != 0:
		logger.error("Failed with code %i stderr %s",retcode,err_out)
		error_count += 1
		sys.exit(1)
	else:
		logger.debug("Succeeded with code %i stderr %s",retcode,err_out)
	key_hash,key_alg,key_name,key_priv = thiskey
	alice_enc_key = key_hash
		
logger.debug("Alice sig key %s",alice_sig_key)
logger.debug("Alice enc key %s",alice_enc_key)
	
logger.debug("Create codecrypt object for Bob")
bob_ccr = codecrypt(ccr_binary,'./bob_keys', debug = True)
logger.debug("Get existing key list for Bob")
retcode,err_out,bob_keys = bob_ccr.list_keys()
if retcode != 0:
	logger.error("Failed with code %i stderr %s",retcode,err_out)
	error_count += 1
	sys.exit(1)

bob_sig_key = None
bob_enc_key = None
for thiskey in bob_keys:
	key_hash,key_alg,key_name,key_priv = thiskey
	logger.debug("key_name=%s,key_alg=%s,key_priv=%s",key_name,key_alg,key_priv)
	if key_name == 'Bob-sign':
		bob_sig_key = key_hash
	elif key_name == 'Bob-enc':
		bob_enc_key = key_hash

if bob_sig_key == None:
	logger.debug("Bob does not have a signature key, creating it will take a few minutes")
	retcode,data_out,err_out,thiskey = bob_ccr.generate_key('Bob-sign','SIG-192')
	if retcode != 0:
		logger.error("Failed with code %i stderr %s",retcode,err_out)
		error_count += 1
		sys.exit(1)
	else:
		logger.debug("Succeeded with code %i stderr %s",retcode,err_out)
	key_hash,key_alg,key_name,key_priv = thiskey
	bob_sig_key = key_hash
		
if bob_enc_key == None:
	logger.debug("Bob does not have an encryption key, creating it")
	retcode,data_out,err_out,thiskey = bob_ccr.generate_key('Bob-enc','ENC-256')
	if retcode != 0:
		logger.error("Failed with code %i stderr %s",retcode,err_out)
		error_count += 1
		sys.exit(1)
	else:
		logger.debug("Succeeded with code %i stderr %s",retcode,err_out)
	key_hash,key_alg,key_name,key_priv = thiskey
	bob_enc_key = key_hash
		
logger.debug("Bob sig key %s",bob_sig_key)
logger.debug("Bob enc key %s",bob_enc_key)

logger.debug("Exporting Alice's public encryption key")
retcode,alice_enc_pubkey,err_out = alice_ccr.export_key(alice_enc_key,ascii_armor = False)
if retcode != 0:
	logger.error("Failed with code %i stderr %s",retcode,err_out)
	error_count += 1
else:
	logger.debug("Succeeded with code %i stderr %s",retcode,err_out)
logger.debug("Exporting Alice's public signature key")
retcode,alice_sig_pubkey,err_out = alice_ccr.export_key(alice_sig_key,ascii_armor = False)
if retcode != 0:
	logger.error("Failed with code %i stderr %s",retcode,err_out)
	error_count += 1
else:
	logger.debug("Succeeded with code %i stderr %s",retcode,err_out)

logger.debug("Exporting Bob's public encryption key")
retcode,bob_enc_pubkey,err_out = bob_ccr.export_key(bob_enc_key,ascii_armor = True)
if retcode != 0:
	logger.error("Failed with code %i stderr %s",retcode,err_out)
	error_count += 1
else:
	logger.debug("Succeeded with code %i stderr %s",retcode,err_out)
logger.debug("Exporting Bob's public signature key")
retcode,bob_sig_pubkey,err_out = bob_ccr.export_key(bob_sig_key,ascii_armor = True)
if retcode != 0:
	logger.error("Failed with code %i stderr %s",retcode,err_out)
	error_count += 1
else:
	logger.debug("Succeeded with code %i stderr %s",retcode,err_out)

logger.debug("Alice view contents of Bob's public signature key")
retcode,err_out,bob_test_key = alice_ccr.list_import_keys(bob_sig_pubkey,ascii_armor = True,secret_key = False)
if retcode != 0:
	logger.error("Failed with code %i stderr %s",retcode,err_out)
	error_count += 1
for thiskey in bob_test_key:
	key_hash,key_alg,key_name,key_priv = thiskey
	logger.debug("key_name=%s,key_alg=%s,key_priv=%s",key_name,key_alg,key_priv)

logger.debug("Import Bob's public encryption key into Alice's keyring")
retcode,data_out,err_out = alice_ccr.import_keys(bob_enc_pubkey,ascii_armor = True)
if retcode != 0:
	logger.error("Failed with code %i stderr %s",retcode,err_out)
	error_count += 1
else:
	logger.debug("Succeeded with code %i stderr %s",retcode,err_out)
logger.debug("Import Bob's public signature key into Alice's keyring")
retcode,data_out,err_out = alice_ccr.import_keys(bob_sig_pubkey,ascii_armor = True)
if retcode != 0:
	logger.error("Failed with code %i stderr %s",retcode,err_out)
	error_count += 1
else:
	logger.debug("Succeeded with code %i stderr %s",retcode,err_out)
	
logger.debug("Import Alice's public encryption key into Bob's keyring")
retcode,data_out,err_out = bob_ccr.import_keys(alice_enc_pubkey,ascii_armor = False)
if retcode != 0:
	logger.error("Failed with code %i stderr %s",retcode,err_out)
	error_count += 1
else:
	logger.debug("Succeeded with code %i stderr %s",retcode,err_out)
logger.debug("Import Alice's public signature key into Bob's keyring")
retcode,data_out,err_out = bob_ccr.import_keys(alice_sig_pubkey,ascii_armor = False)
if retcode != 0:
	logger.error("Failed with code %i stderr %s",retcode,err_out)
	error_count += 1
else:
	logger.debug("Succeeded with code %i stderr %s",retcode,err_out)
	
logger.debug("Alice export secret signature key")
retcode,alice_sig_seckey,err_out = alice_ccr.export_key(alice_sig_key,ascii_armor = False,secret_key = True)
if retcode != 0:
	logger.error("Failed with code %i stderr %s",retcode,err_out)
	error_count += 1
else:
	logger.debug("Succeeded with code %i stderr %s",retcode,err_out)
logger.debug("Bob view Alice's exported secret signature key")
retcode,err_out,alice_test_key = bob_ccr.list_import_keys(alice_sig_seckey,ascii_armor = False,secret_key = True)
if retcode != 0:
	logger.error("Failed with code %i stderr %s",retcode,err_out)
	error_count += 1
else:
	logger.debug("Succeeded with code %i stderr %s",retcode,err_out)
for thiskey in alice_test_key:
	key_hash,key_alg,key_name,key_priv = thiskey
	logger.debug("key_name=%s,key_alg=%s,key_priv=%s",key_name,key_alg,key_priv)

logger.debug("Lock Alice secret signature key with a password")
alice_ccr.set_keyring_password(lock_password)
retcode,data_out,err_out = alice_ccr.lock_key(alice_sig_key)
if retcode != 0:
	logger.error("Failed with code %i stderr %s",retcode,err_out)
	error_count += 1
else:
	logger.debug("Succeeded with code %i stderr %s",retcode,err_out)

alice_ccr.set_keyring_password('')
logger.debug("Attempt to sign without password - should fail")
test_pt = "binary signature test".encode('utf-8')
retcode,test_ct,err_out,sigs_remain = alice_ccr.generate_signature(alice_sig_key,test_pt,ascii_armor = False,cleartext_mode = False)
if retcode == 0:
	logger.error("Succeeded but should have failed with code %i stderr %s",retcode,err_out)
	error_count += 1
else:
	logger.debug("Failed as expected with code %i stderr %s",retcode,err_out)

alice_ccr.set_keyring_password(lock_password)
logger.debug("Generating binary object signed by Alice")
retcode,test_ct,err_out,sigs_remain = alice_ccr.generate_signature(alice_sig_key,test_pt,ascii_armor = False,cleartext_mode = False)
if retcode != 0:
	logger.error("Failed with code %i stderr %s",retcode,err_out)
	error_count += 1
else:
	logger.debug("Succeeded with code %i sigs remaining %i stderr %s",retcode,sigs_remain,err_out)

logger.debug("Bob checking signature on binary object signed by Alice")
retcode,test_pt_out,err_out,signature_good,details = bob_ccr.verify_signature(test_ct,ascii_armor = False,cleartext_mode = False)
if retcode != 0 or signature_good == False:
	logger.error("Failed with code %i stderr %s",retcode,err_out)
	error_count += 1
else:
	logger.debug("Succeeded with details %s",details)
if signature_good != True:
	logger.error("Signature reported bad, should have been good, code %i stderr %s",retcode,err_out)
	error_count += 1
if test_pt != test_pt_out:
	logger.debug("Signature reported good but output does not equal input, code %i stderr %s",retcode,err_out)
	logger.error("got %s exp %s",test_ct_out,test_ct)
	error_count += 1

logger.debug("Generating ascii object signed by Bob")
test_pt = "ascii signature test".encode('utf-8')
retcode,test_ct,err_out,sigs_remain = bob_ccr.generate_signature(bob_sig_key,test_pt,ascii_armor = True,cleartext_mode = False)
if retcode != 0:
	logger.error("Failed with code %i stderr %s",retcode,err_out)
	error_count += 1
else:
	logger.debug("Succeeded with code %i sigs remaining %i",retcode,sigs_remain)

logger.debug("Alice checking signature on ascii object signed by Bob")
retcode,test_pt_out,err_out,signature_good,details = alice_ccr.verify_signature(test_ct,ascii_armor = True,cleartext_mode = False)
if retcode != 0 or signature_good == False:
	logger.error("Failed with code %i stderr %s",retcode,err_out)
	error_count += 1
if signature_good != True:
	logger.error("Signature reported bad, should have been good, code %i stderr %s",retcode,err_out)
	error_count += 1
if test_pt != test_pt_out:
	logger.debug("Signature reported good but output does not equal input, code %i stderr %s",retcode,err_out)
	logger.error("got %s exp %s",test_ct_out,test_ct)
	error_count += 1

logger.debug("Generating clear object signed by Alice")
test_pt = "clear signature test".encode('utf-8')
retcode,test_ct,err_out,sigs_remain = alice_ccr.generate_signature(alice_sig_key,test_pt,ascii_armor = False,cleartext_mode = True)
if retcode != 0:
	logger.error("Failed with code %i stderr %s",retcode,err_out)
	error_count += 1
else:
	logger.debug("Succeeded with code %i sigs remaining %i",retcode,sigs_remain)

logger.debug("Bob checking signature on clear object signed by Alice")
retcode,test_pt_out,err_out,signature_good,details = bob_ccr.verify_signature(test_ct,ascii_armor = False,cleartext_mode = True)
if retcode != 0 or signature_good == False:
	logger.error("Failed with code %i stderr %s",retcode,err_out)
	error_count += 1
if signature_good != True:
	logger.error("Signature reported bad, should have been good, code %i stderr %s",retcode,err_out)
	error_count += 1
if test_pt != test_pt_out:
	logger.debug("Signature reported good but output does not equal input, code %i stderr %s",retcode,err_out)
	logger.error("got %s exp %s",test_ct_out,test_ct)
	error_count += 1

test_ct = test_ct.decode('utf-8').replace("clear signature test","clear signature Test").encode('utf-8')
logger.debug("Bob checking signature on altered clear object signed by Alice")
retcode,test_pt_out,err_out,signature_good,details = bob_ccr.verify_signature(test_ct,ascii_armor = False,cleartext_mode = True)
if retcode == 0 or signature_good == True:
	logger.error("Signature good but should have been bad, code %i stderr %s sig-good %s",retcode,err_out,signature_good)
	error_count += 1
if signature_good != True:
	logger.debug("Signature correctly reported bad, code %i details %s",retcode,details)

logger.debug("Generating detached binary object signed by Bob")
test_pt = "binary detached signature test".encode('utf-8')
retcode,test_ct,err_out,sigs_remain = bob_ccr.generate_detached_signature(bob_sig_key,test_pt,ascii_armor = False)
if retcode != 0:
	logger.error("Failed with code %i stderr %s",retcode,err_out)
	error_count += 1
else:
	logger.debug("Succeeded with code %i sigs remaining %i",retcode,sigs_remain)

logger.debug("Alice verifying detached binary object signed by Bob")
retcode,data_out,err_out,signature_good,details = alice_ccr.verify_detached_signature(test_pt,test_ct,ascii_armor = False)
if retcode != 0 or signature_good == False:
	logger.error("Failed with code %i stderr %s",retcode,err_out)
	error_count += 1
if signature_good != True:
	logger.error("Signature reported bad, should have been good, code %i stderr %s",retcode,err_out)
	error_count += 1

logger.debug("Alice verifying altered detached binary object signed by Bob")
test_pt = test_pt.decode('utf-8').replace("test","teSt").encode('utf-8')
retcode,data_out,err_out,signature_good,details = alice_ccr.verify_detached_signature(test_pt,test_ct,ascii_armor = False)
if retcode == 0 or signature_good == True:
	logger.error("Signature good but should have been bad, code %i stderr %s sig-good %s",retcode,err_out,signature_good)
	error_count += 1
if signature_good != True:
	logger.debug("Signature correctly reported bad, code %i details %s",retcode,details)

logger.debug("Generating detached ascii object signed by Alice")
test_pt = "ascii detached signature test".encode('utf-8')
retcode,test_ct,err_out,sigs_remain = alice_ccr.generate_detached_signature(alice_sig_key,test_pt,ascii_armor = True)
if retcode != 0:
	logger.error("Failed with code %i stderr %s",retcode,err_out)
	error_count += 1
else:
	logger.debug("Succeeded with code %i sigs remaining %i",retcode,sigs_remain)

logger.debug("Bob verifying detached ascii object signed by Alice")
retcode,data_out,err_out,signature_good,details = bob_ccr.verify_detached_signature(test_pt,test_ct,ascii_armor = True)
if retcode != 0 or signature_good == False:
	logger.error("Failed with code %i stderr %s",retcode,err_out)
	error_count += 1
if signature_good != True:
	logger.error("Signature reported bad, should have been good, code %i stderr %s",retcode,err_out)
	error_count += 1

logger.debug("Bob verifying altered detached ascii object signed by Alice")
test_pt = test_pt.decode('utf-8').replace("test","teSt").encode('utf-8')
retcode,data_out,err_out,signature_good,details = bob_ccr.verify_detached_signature(test_pt,test_ct,ascii_armor = True)
if retcode == 0 or signature_good == True:
	logger.error("Signature good but should have been bad, code %i stderr %s sig-good %s",retcode,err_out,signature_good)
	error_count += 1
if signature_good != True:
	logger.debug("Signature correctly reported bad, code %i details %s",retcode,details)

logger.debug("Generating encrypted binary message from Bob to Alice")
test_pt = "encrypted binary message from Bob to Alice".encode('utf-8')
retcode,test_ct,err_out = bob_ccr.encrypt(alice_enc_key,test_pt,ascii_armor = False)
if retcode != 0:
	logger.error("Failed with code %i stderr %s",retcode,err_out)
	error_count += 1

logger.debug("Alice decrypting binary message from Bob")
retcode,test_pt_out,err_out,details = alice_ccr.decrypt(test_ct,ascii_armor = False)
if retcode != 0:
	logger.error("Failed with code %i stderr %s",retcode,err_out)
	error_count += 1
else:
	logger.debug("Succeeded with code %i details %s",retcode,details)
	if test_pt_out != test_pt:
		logger.error("Reported success but data bad, got %s, exp %s",test_pt_out,test_pt)
		error_count += 1

logger.debug("Bob trying to decrypt own message")
retcode,test_pt_out,err_out,details = bob_ccr.decrypt(test_ct,ascii_armor = False)
if retcode == 0 or test_pt_out == test_pt:
	logger.error("Succeeded but should have failed with code %i stderr %s",retcode,err_out)
	error_count += 1
else:
	logger.debug("Failed as expected with code %i stderr %s",retcode,err_out)

logger.debug("Generating encrypted ascii message from Alice to Bob")
test_pt = "encrypted ascii message from Alice to Bob".encode('utf-8')
retcode,test_ct,err_out = alice_ccr.encrypt(bob_enc_key,test_pt,ascii_armor = True)
if retcode != 0:
	logger.error("Failed with code %i stderr %s",retcode,err_out)
	error_count += 1

logger.debug("Bob decrypting ascii message from Alice")
retcode,test_pt_out,err_out,details = bob_ccr.decrypt(test_ct,ascii_armor = True)
if retcode != 0:
	logger.error("Failed with code %i stderr %s",retcode,err_out)
	error_count += 1
else:
	logger.debug("Succeeded with code %i details %s",retcode,details)
	if test_pt_out != test_pt:
		logger.error("Reported success but data bad, got %s, exp %s",test_pt_out,test_pt)
		error_count += 1

logger.debug("Generating encrypted and signed binary message from Bob to Alice")
test_pt = "encrypted and signed binary message from Bob to Alice".encode('utf-8')
retcode,test_ct,err_out,sigs_remain = bob_ccr.encrypt_sign(bob_sig_key,alice_enc_key,test_pt,ascii_armor = False)
if retcode != 0:
	logger.error("Failed with code %i stderr %s",retcode,err_out)
	error_count += 1
else:
	logger.debug("Succeeded with code %i sigs remaining %i",retcode,sigs_remain)

logger.debug("Alice decrypting and checking binary message from Bob")
retcode,test_pt_out,err_out,signature_good,details = alice_ccr.decrypt_verify(test_ct,ascii_armor = False)
if retcode != 0:
	logger.error("Failed with code %i stderr %s",retcode,err_out)
	error_count += 1
else:
	logger.debug("Succeeded with code %i sig-good %s details %s",retcode,signature_good,details)
	if test_pt_out != test_pt:
		logger.error("Reported success but data bad, got %s, exp %s",test_pt_out,test_pt)
		error_count += 1

logger.debug("Bob trying to decrypt own message")
retcode,test_pt_out,err_out,signature_good,details = bob_ccr.decrypt_verify(test_ct,ascii_armor = False)
if retcode == 0 or test_pt_out == test_pt:
	logger.error("Succeeded but should have failed with code %i stderr %s",retcode,err_out)
	error_count += 1
else:
	logger.debug("Failed as expected with code %i stderr %s",retcode,err_out)

logger.debug("Generating encrypted and signed ascii message from Alice to Bob")
test_pt = "encrypted and signed ascii message from Alice to Bob".encode('utf-8')
retcode,test_ct,err_out,sigs_remain = alice_ccr.encrypt_sign(alice_sig_key,bob_enc_key,test_pt,ascii_armor = True)
if retcode != 0:
	logger.error("Failed with code %i stderr %s",retcode,err_out)
	error_count += 1

logger.debug("Bob decrypting and checking ascii message from Alice")
retcode,test_pt_out,err_out,signature_good,details = bob_ccr.decrypt_verify(test_ct,ascii_armor = True)
if retcode != 0:
	logger.error("Failed with code %i stderr %s",retcode,err_out)
	error_count += 1
else:
	logger.debug("Succeeded with code %i sig-good %s details %s",retcode,signature_good,details)
	if test_pt_out != test_pt:
		logger.error("Reported success but data bad, got %s, exp %s",test_pt_out,test_pt)
		error_count += 1

logger.debug("Alice deleting Bob's public signature key")
retcode,data_out,err_out = alice_ccr.delete_key(bob_sig_key)
if retcode != 0:
	logger.error("Failed with code %i stderr %s",retcode,err_out)
	error_count += 1
else:
	logger.debug("Succeeded with code %i stderr %s",retcode,err_out)

logger.debug("Alice deleting Bob's public encryption key")
retcode,data_out,err_out = alice_ccr.delete_key(bob_enc_key)
if retcode != 0:
	logger.error("Failed with code %i stderr %s",retcode,err_out)
	error_count += 1
else:
	logger.debug("Succeeded with code %i stderr %s",retcode,err_out)

logger.debug("Bob renaming Alice's signature key")
retcode,data_out,err_out = bob_ccr.rename_key('Alice-sign','Alice-byebye')
if retcode != 0:
	logger.error("Failed with code %i stderr %s",retcode,err_out)
	error_count += 1
else:
	logger.debug("Succeeded with code %i stderr %s",retcode,err_out)
	
logger.debug("Bob renaming Alice's encryption key")
retcode,data_out,err_out = bob_ccr.rename_key('Alice-enc','Alice-delete')
if retcode != 0:
	logger.error("Failed with code %i stderr %s",retcode,err_out)
	error_count += 1
else:
	logger.debug("Succeeded with code %i stderr %s",retcode,err_out)
	
logger.debug("Bob renaming Alice's encryption key again, should fail")
retcode,data_out,err_out = bob_ccr.rename_key('Alice-enc','Alice-delete')
if retcode != 0:
	logger.debug("Failed as expected with code %i stderr %s",retcode,err_out)
else:
	logger.error("Succeeded but should have failed with code %i stderr %s",retcode,err_out)
	error_count += 1
	
logger.debug("Bob deleting Alice's signature key")
retcode,data_out,err_out = bob_ccr.delete_key('Alice-byebye')
if retcode != 0:
	logger.error("Failed with code %i stderr %s",retcode,err_out)
	error_count += 1
else:
	logger.debug("Succeeded with code %i stderr %s",retcode,err_out)
	
logger.debug("Bob deleting Alice's encryption key")
retcode,data_out,err_out = bob_ccr.delete_key('Alice-delete')
if retcode != 0:
	logger.error("Failed with code %i stderr %s",retcode,err_out)
	error_count += 1
else:
	logger.debug("Succeeded with code %i stderr %s",retcode,err_out)
	
logger.debug("Bob deleting Alice's encryption key again, should fail")
retcode,data_out,err_out = bob_ccr.delete_key('Alice-delete')
if retcode != 0:
	logger.debug("Failed as expected with code %i stderr %s",retcode,err_out)
else:
	logger.error("Succeeded but should have failed with code %i stderr %s",retcode,err_out)
	error_count += 1
	
logger.debug("Unlock Alice's signature key")
retcode,data_out,err_out = alice_ccr.unlock_key(alice_sig_key)
if retcode != 0:
	logger.error("Failed with code %i stderr %s",retcode,err_out)
	error_count += 1
else:
	logger.debug("Succeeded with code %i stderr %s",retcode,err_out)

if error_count == 0:
	logger.debug("error count = %i",error_count)
	sys.exit(0)
else:
	logger.error("error count = %i",error_count)
	sys.exit(1)


# EOF
