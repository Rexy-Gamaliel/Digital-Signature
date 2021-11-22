import PySimpleGUI as sg

from gui_windows import *
from gui_event_handlers import *
import utility as util

from ecc import *

'''
Theme
'''
sg.theme("DarkTeal12")

'''
All Windows
'''
all_windows = [
	[
		sg.Column(window_main_menu, key="window_main_menu"),
		sg.Column(window_keygen, key="window_keygen", visible=False),
		sg.Column(window_signing, key="window_signing", visible=False),
		sg.Column(window_verifying, key="window_verifying", visible=False)
	]
]

'''
Runner
'''
def run_gui():
	window = sg.Window("Digital-Signature", all_windows, size=WIN_SIZE, element_justification="c")
	ecc = ECC()
	ecc.initiate(generate_new_config=True, generate_new_keys=True)

	while True:
		cur_events, cur_values = window.read()

		# window handlers

		if "Pembangkitan Kunci" in cur_events:
			window["window_main_menu"].update(visible=False)
			window["window_keygen"].update(visible=True)

		if "Pembangkitan Tanda Tangan Digital" in cur_events:
			window["window_main_menu"].update(visible=False)
			window["window_signing"].update(visible=True)

		if "Verifikasi Tanda Tangan Digital" in cur_events:
			window["window_main_menu"].update(visible=False)
			window["window_verifying"].update(visible=True)

		if "Kembali ke menu utama" in cur_events:
			window["window_keygen"].update(visible=False)
			window["window_signing"].update(visible=False)
			window["window_verifying"].update(visible=False)
			window["window_main_menu"].update(visible=True)

		# keygen handlers

		if "Bangkitkan kunci" in cur_events:
			handle_event_keygen(window, cur_values, ecc)

		if "Simpan kunci privat" in cur_events:
			handle_event_save_private_key(cur_values)

		if "Simpan kunci publik" in cur_events:
			handle_event_save_public_key(cur_values)

		# signing handlers

		if cur_values["signing_private_key_filename"]:
			path = cur_values["signing_private_key_filename"]
			content = ""
			with open(path, "r") as file:
				content = file.read()
			window["signing_private_key"].update(content)

		if cur_values["signing_option_1"]:
			window["signing_signature_option_container_1"].update(visible=True)
			window["signing_signature_option_container_2"].update(visible=False)
			window["signing_result_document_filename"].update("")
		elif cur_values["signing_option_2"]:
			window["signing_signature_option_container_1"].update(visible=False)
			window["signing_signature_option_container_2"].update(visible=True)
			window["signing_result_document_filename"].update(os.path.abspath("DUMMY"))
			window["signing_signature_filename"].update("")

		if "Bangkitkan tanda tangan digital" in cur_events:
			handle_event_signing(cur_values)

		# verifying handlers

		if cur_values["verifying_public_key_filename"]:
			path = cur_values["verifying_public_key_filename"]
			content = ""
			with open(path, "r") as file:
				content = file.read()
			window["verifying_public_key"].update(content)

		if cur_values["verifying_option_1"]:
			window["verifying_signature_picker_container"].update(visible=False)
		else:
			window["verifying_signature_picker_container"].update(visible=True)
			window["verifying_signature_filename"].update("")

		if "Verifikasi tanda tangan digital" in cur_events:
			handle_event_verifying(cur_values)

		if cur_events == sg.WIN_CLOSED or 'Quit' in cur_events:
			break

	window.close()

if __name__ == "__main__":
	run_gui()