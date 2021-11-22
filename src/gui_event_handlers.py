import PySimpleGUI as sg
import os
from digital_sign import *
import utility as util
from constant import DEMO_DIR

'''
Event Handlers
'''

# Keygen

def handle_event_keygen(window, values, ecc: ECC):
	ecc.update_keys()
	ecc.read_keys()
	private_key = ""
	private_key = ecc.private_key_info()
	# with open(os.path.abspath("src/config/ecc-private.txt"), "r") as file:
	# 	private_key = file.read()
	public_key = ""
	public_key = ecc.public_key_info()
	# with open(os.path.abspath("src/config/ecc-public.txt"), "r") as file:
	# 	public_key = file.read()
	window["keygen_private_key"].update(private_key)
	window["keygen_public_key"].update(public_key)

def handle_event_save_private_key(values, ecc: ECC):
	try:
		# with open(values["keygen_private_key_filename"], "w") as file:
		# 	file.write(values["keygen_private_key"])
		ecc.store_private_keys(values["keygen_private_key_filename"])
		sg.popup("Kunci privat berhasil disimpan!")
	except:
		sg.popup("Penyimpanan gagal!")

def handle_event_save_public_key(values, ecc: ECC):
	try:
		# with open(values["keygen_public_key_filename"], "w") as file:
		# 	file.write(values["keygen_public_key"])
		ecc.store_public_keys(values["keygen_public_key_filename"])
		sg.popup("Kunci publik berhasil disimpan!")
	except:
		sg.popup("Penyimpanan gagal!")

# Signing

def handle_event_signing(values):
	# cek eksistensi file
	if not os.path.isfile(values["signing_document_filename"]):
		sg.popup("File dokumen tidak ditemukan!")
		return
	if not os.path.isfile(values["signing_private_key_filename"]):
		sg.popup("File kunci privat tidak ditemukan!")
		return
	# buat tanda tangan digital
	try:
		if values["signing_option_1"]:
			sign_txt(
				values["signing_document_filename"],
				values["signing_result_document_filename"],
				values["signing_private_key_filename"],
				pisah=False
			)
			# os.remove(os.path.abspath(values["signing_result_document_filename"]))
		else:
			sign_txt(
				values["signing_document_filename"],
				values["signing_signature_filename"],
				values["signing_private_key_filename"],
				pisah=True
			)
			# os.remove(os.path.abspath(values["signing_signature_filename"]))
	except:
		sg.popup("Pembangkitan tanda tangan digital gagal!")
		return
	# # simpan tanda tangan digital
	# if values["signing_option_1"]:
	# 	# simpan tanda tangan di dokumen
	# 	# secara default sudah dilakukan sign_txt()
	# 	pass
	# else:
	# 	# simpan tanda tangan secara terpisah
	# 	# ambil dan simpan file tanda tangan
	# 	try:
	# 		path = os.path.abspath("src/demo/signature.sgn")
	# 		signature_content = ""
	# 		with open(path, "r") as file:
	# 			signature_content = file.read()
	# 		util.writetxt(values["signing_signature_filename"], signature_content)
	# 	except:
	# 		sg.popup("Penyimpanan tanda tangan digital gagal!")
	# 		return
	# 	# hapus hasil sign_txt()
	# 	os.remove(os.path.abspath(values["signing_result_document_filename"]))

	sg.popup("Tanda tangan digital berhasil disimpan!")

# verifying

def handle_event_verifying(values):
	# cek eksistensi file
	if not os.path.isfile(values["verifying_document_filename"]):
		sg.popup("File dokumen tidak ditemukan!")
		return
	if not os.path.isfile(values["verifying_public_key_filename"]):
		sg.popup("File kunci publik tidak ditemukan!")
		return
	if values["verifying_option_2"] and not os.path.isfile(values["verifying_signature_filename"]):
		sg.popup("File tanda tangan tidak ditemukan!")
		return

	# verifikasi tanda tangan
	res = False
	if values["verifying_option_1"]:
		# tanda tangan ada di file dokumen
		document_filename = values["verifying_document_filename"]
		public_key_filename = values["verifying_public_key_filename"]
		try:
			res = verify_sign(document_filename, public_key_filename)
		except:
			sg.popup("Tanda tangan digital tidak otentik!")
			return
	else:
		# tanda tangan ada di file terpisah
		document_filename = values["verifying_document_filename"]
		signature_filename = values["verifying_signature_filename"]
		public_key_filename = values["verifying_public_key_filename"]
		try:
			res = verify_sign_with_file(document_filename, signature_filename, public_key_filename)
		except:
			sg.popup("Tanda tangan digital tidak otentik!")
			return
	if res:
		sg.popup("Tanda tangan digital otentik!")
	else:
		sg.popup("Tanda tangan digital tidak otentik!")