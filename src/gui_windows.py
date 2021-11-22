import PySimpleGUI as sg
import os
from gui_constants import *

'''
Windows
'''
window_main_menu = [
	[sg.Text("Digital-Signature", size=TEXTBOX_SIZE, justification="center")],
	[sg.Button("Pembangkitan Kunci", size=BTN_SIZE_1)],
    [sg.Button("Pembangkitan Tanda Tangan Digital", size=BTN_SIZE_1)],
    [sg.Button("Verifikasi Tanda Tangan Digital", size=BTN_SIZE_1)],
    [sg.Button("Quit", size=BTN_SIZE_1)]
]

window_keygen = [
	[sg.Column([[sg.Text("Pembangkitan Kunci", size=TEXTBOX_SIZE, justification="center")]], justification="center")],
	[
		sg.Column([
			[sg.Text("Kunci Publik:")],
			[sg.Multiline(key="keygen_public_key", size=MULTILINE_SIZE, disabled=True)],
			[
				sg.FileSaveAs(target="keygen_public_key_filename", button_text="Pilih file", size=BTN_SIZE_2, file_types=(("public key", "*.pub"),)),
				sg.Button("Simpan kunci publik", size=BTN_SIZE_2)
			],
			[sg.InputText(key="keygen_public_key_filename", size=INPUTTEXT_SIZE, disabled=True)]
		]),
		sg.Column([
			[sg.Text("Kunci Privat:")],
			[sg.Multiline(key="keygen_private_key", size=MULTILINE_SIZE, disabled=True)],
			[
				sg.FileSaveAs(target="keygen_private_key_filename", button_text="Pilih file", size=BTN_SIZE_2, file_types=(("private key", "*.pri"),)),
				sg.Button("Simpan kunci privat", size=BTN_SIZE_2)
			],
			[sg.InputText(key="keygen_private_key_filename", size=INPUTTEXT_SIZE, disabled=True)]
		]),
	],
	[sg.Column([[sg.Button("Bangkitkan kunci", size=BTN_SIZE_1)]], justification="center")],
	[sg.Column([[sg.Button("Kembali ke menu utama", size=BTN_SIZE_1)]], justification="center")],
]

window_signing = [
	[sg.Column([[sg.Text("Pembangkitan Tanda Tangan Digital", size=TEXTBOX_SIZE, justification="center")]], justification="center")],
	
	[
		sg.Column([
			[sg.Text("Buka")],
			[sg.Text("File Dokumen:")],
			[
				sg.FileBrowse(target="signing_document_filename", button_text="Pilih file", size=BTN_SIZE_2), 
				sg.InputText(key="signing_document_filename", disabled=True, size=BTN_SIZE_2)
			],
			[sg.Text("Kunci Privat:")],
			[
				sg.FileBrowse(target="signing_private_key_filename", button_text="Pilih file", size=BTN_SIZE_2, file_types=(("private key", "*.pri"),)), 
				sg.InputText(key="signing_private_key_filename", disabled=True, size=BTN_SIZE_2, enable_events=True)
			],
			[sg.Multiline(key="signing_private_key", disabled=True, size=MULTILINE_SIZE)]
		]),
		sg.Column([
			[sg.Text("Simpan")],
			[sg.Radio("Sisipkan tanda tangan pada dokumen", "signing_option", key="signing_option_1", enable_events=True, default=True)],
			[sg.Radio("Simpan tanda tangan secara terpisah", "signing_option", key="signing_option_2", enable_events=True)],
			[
				sg.Column([
					[sg.Text("File Dokumen:")],
					[
						sg.FileSaveAs(target="signing_result_document_filename", button_text="Pilih file", size=BTN_SIZE_2), 
						sg.InputText(key="signing_result_document_filename", disabled=True, size=BTN_SIZE_2)
					]
				], key="signing_signature_option_container_1"),
				sg.Column([
					[sg.Text("File Tanda Tangan:", key="signature_text")],
					[
						sg.FileSaveAs(target="signing_signature_filename", button_text="Pilih file", size=BTN_SIZE_2, file_types=(("digital signature", "*.sgn"),)),
						sg.InputText(key="signing_signature_filename", disabled=True, size=BTN_SIZE_2)
					]
				], key="signing_signature_option_container_2", visible=False)
			]
		])
	],

	[sg.Column([[sg.Button("Bangkitkan tanda tangan digital", size=BTN_SIZE_1)]], justification="center")],
	[sg.Column([[sg.Button("Kembali ke menu utama", size=BTN_SIZE_1)]], justification="center")],
]

window_verifying = [
	[sg.Column([[sg.Text("Verifikasi Tanda Tangan Digital", size=TEXTBOX_SIZE, justification="center")]], justification="center")],
	
	[sg.Column([
		[sg.Text("Buka")],
		[sg.Radio("Tanda tangan berada di file dokumen", "verifying_option", key="verifying_option_1", enable_events=True)],
		[sg.Radio("Tanda tangan berada di file terpisah", "verifying_option", key="verifying_option_2", enable_events=True, default=True)],
		[sg.Column([
			[sg.Text("File dokumen:")],
			[
				sg.FileBrowse(target="verifying_document_filename", button_text="Pilih File", size=BTN_SIZE_2), 
				sg.InputText(key="verifying_document_filename", disabled=True, size=BTN_SIZE_2)
			],
		])],
		[sg.Column([
			[sg.Text("File tanda tangan:")],
			[
				sg.FileBrowse(target="verifying_signature_filename", button_text="Pilih file", size=BTN_SIZE_2, file_types=(("digital signature", "*.sgn"),)), 
				sg.InputText(key="verifying_signature_filename", disabled=True, size=BTN_SIZE_2)
			]
		], key="verifying_signature_picker_container")],
		[sg.Column([
			[sg.Text("Kunci Publik:")],
			[
				sg.FileBrowse(target="verifying_public_key_filename", button_text="Pilih File", size=BTN_SIZE_2, file_types=(("public key", "*.pub"),)), 
				sg.InputText(key="verifying_public_key_filename", disabled=True, size=BTN_SIZE_2, enable_events=True)
			],
			[sg.Multiline(key="verifying_public_key", size=MULTILINE_SIZE)]
		])]
	], justification="center")],

	[sg.Column([[sg.Button("Verifikasi tanda tangan digital", size=BTN_SIZE_1)]], justification="center")],
	[sg.Column([[sg.Button("Kembali ke menu utama", size=BTN_SIZE_1)]], justification="center")],
]