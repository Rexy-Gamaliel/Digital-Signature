import PySimpleGUI as sg

from gui_windows import *
from gui_event_handlers import *

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

		if "Pembangkitan Kunci" in cur_events:
			window["window_main_menu"].update(visible=False)
			window["window_keygen"].update(visible=True)

		if "Pembangkitan Tanda Tangan Digital" in cur_events:
			window["window_main_menu"].update(visible=False)
			window["window_signing"].update(visible=True)

		if "Verifikasi Tanda Tangan Digital" in cur_events:
			window["window_main_menu"].update(visible=False)
			window["window_verifying"].update(visible=True)

		if "Bangkitkan Kunci" in cur_events:
			handle_event_keygen(window, cur_values, ecc)

		if cur_values["signing_option_1"]:
			window["signature_option_container"].update(visible=False)
		elif cur_values["signing_option_2"]:
			window["signature_option_container"].update(visible=True)

		if "Kembali ke Menu Utama" in cur_events:
			window["window_keygen"].update(visible=False)
			window["window_signing"].update(visible=False)
			window["window_verifying"].update(visible=False)
			window["window_main_menu"].update(visible=True)

		if cur_events == sg.WIN_CLOSED or 'Quit' in cur_events:
			break

	window.close()

run_gui()