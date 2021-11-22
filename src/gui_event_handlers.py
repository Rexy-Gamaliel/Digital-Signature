import PySimpleGUI as sg
import os
from digital_sign import *
import utility as util

'''
Event Handlers
'''

# Keygen

def handle_event_keygen(window, values, ecc):
	ecc.generate_keys()
	private_key_string = \
		str(ecc.get_config_a()) + " " + \
		str(ecc.get_config_b()) + " " + \
		str(ecc.get_config_p()) + "\n" + \
		str(ecc.get_key_pri_a()) + " " + \
		str(ecc.get_key_pri_b())
	public_key_a = ecc.get_key_point_a()
	public_key_b = ecc.get_key_point_b()
	public_key_string = str(public_key_a[0]) + " " + str(public_key_a[1]) + "\n" + str(public_key_b[0]) + " " + str(public_key_b[1])
	window["keygen_private_key"].update(private_key_string)
	window["keygen_public_key"].update(public_key_string)

def handle_event_save_private_key(values):
	try:
		with open(values["keygen_private_key_filename"], "w") as file:
			file.write(values["keygen_private_key"])
		sg.popup("Kunci privat berhasil disimpan!")
	except:
		sg.popup("Penyimpanan gagal!")

def handle_event_save_public_key(values):
	try:
		with open(values["keygen_public_key_filename"], "w") as file:
			file.write(values["keygen_public_key"])
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
		signed_document = sign_txt( \
			values["signing_document_filename"], \
			values["signing_result_document_filename"], \
			values["signing_private_key_filename"])
	except:
		sg.popup("Pembangkitan tanda tangan digital gagal!")
		return

	# simpan tanda tangan digital
	if values["signing_option_1"]:
		# simpan tanda tangan di dokumen
		# secara default sudah dilakukan sign_txt()
		pass
	else:
		# simpan tanda tangan secara terpisah
		# ambil dan simpan file tanda tangan
		try:
			# signature_content = util.readtxt(os.path.join(os.path.abspath(), "src/test/ecc-encrypted"))
			print("yey")
			print(os.path.abspath("src/test/ecc-encrypted"))
			path = os.path.abspath("src/test/ecc-encrypted")
			print(path)
			signature_content = ""
			with open(path, "r") as file:
				signature_content = file.read()
			util.writetxt(values["signing_signature_filename"], signature_content)
		except:
			sg.popup("Penyimpanan tanda tangan digital gagal!")
			return
		# hapus hasil sign_txt()

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
		res = verify_sign(document_filename, public_key_filename)
	else:
		# tanda tangan ada di file terpisah
		document_filename = values["verifying_document_filename"]
		signature_filename = values["verifying_signature_filename"]
		public_key_filename = values["verifying_public_key_filename"] 
		res = verify_sign_with_file(document_filename, signature_filename, public_key_filename)
	if res:
		sg.popup("Tanda tangan digital otentik!")
	else:
		sg.popup("Tanda tangan digital tidak otentik!")