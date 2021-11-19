import PySimpleGUI as sg
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
			[sg.Multiline(key="public_key", size=MULTILINE_SIZE, disabled=True)],
			[
				sg.FileSaveAs(target="public_key_filename", button_text="Pilih File", size=BTN_SIZE_2),
				sg.Button("Simpan dalam File", size=BTN_SIZE_2)
			],
			[sg.InputText("nama file", key="public_key_filename", size=INPUTTEXT_SIZE, disabled=True)]
		]),
		sg.Column([
			[sg.Text("Kunci Privat:")],
			[sg.Multiline(key="private_key", size=MULTILINE_SIZE, disabled=True)],
			[
				sg.FileSaveAs(target="private_key_filename", button_text="Pilih File", size=BTN_SIZE_2),
				sg.Button("Simpan dalam File", size=BTN_SIZE_2)
			],
			[sg.InputText("nama file", key="private_key_filename", size=INPUTTEXT_SIZE, disabled=True)]
		]),
	],
	[sg.Column([[sg.Button("Bangkitkan Kunci", size=BTN_SIZE_1)]], justification="center")],
	[sg.Column([[sg.Button("Kembali ke Menu Utama", size=BTN_SIZE_1)]], justification="center")],
]

window_signing = [
	[sg.Column([[sg.Text("Pembangkitan Tanda Tangan Digital", size=TEXTBOX_SIZE, justification="center")]], justification="center")],
	
	[
		sg.Column([
			[sg.Text("Buka")],
			[sg.Text("File Dokumen:")],
			[
				sg.FileBrowse(target="document_filename", button_text="Pilih File", size=BTN_SIZE_2), 
				sg.InputText(key="document_filename", disabled=True, size=BTN_SIZE_2)
			],
			[sg.Text("Kunci Privat:")],
			[
				sg.FileBrowse(target="private_key_filename", button_text="Pilih File", size=BTN_SIZE_2), 
				sg.InputText(key="private_key_filename", disabled=True, size=BTN_SIZE_2)
			],
			[sg.Multiline(key="private_key", size=MULTILINE_SIZE)]
		]),
		sg.Column([
			[sg.Text("Simpan")],
			[sg.Radio("Sisipkan tanda tangan pada dokumen", "signing_option", key="signing_option_1", enable_events=True)],
			[sg.Radio("Simpan tanda tangan secara terpisah", "signing_option", key="signing_option_2", enable_events=True, default=True)],
			[sg.Column([
				[sg.Text("File Dokumen:")],
				[
					sg.FileBrowse(target="result_document_filename", button_text="Pilih File", size=BTN_SIZE_2), 
					sg.InputText(key="result_document_filename", disabled=True, size=BTN_SIZE_2)
				]
			])],
			[sg.Column([
				[sg.Text("File Tanda Tangan:", key="signature_text")],
				[
					sg.FileBrowse(key="signature_file_picker", target="signature_filename", button_text="Pilih File", size=BTN_SIZE_2),
					sg.InputText(key="signature_filename", disabled=True, size=BTN_SIZE_2)
				]
			], key="signature_option_container")]
		])
	],

	[sg.Column([[sg.Button("Bangkitkan Tanda Tangan Digital", size=BTN_SIZE_1)]], justification="center")],
	[sg.Column([[sg.Button("Kembali ke Menu Utama", size=BTN_SIZE_1)]], justification="center")],
]

window_verifying = [
	[sg.Column([[sg.Text("Verifikasi Tanda Tangan Digital", size=TEXTBOX_SIZE, justification="center")]], justification="center")],
	
	[sg.Column([
		[sg.Text("Buka")],
		[sg.Text("File Dokumen:")],
		[
			sg.FileBrowse(target="document_filename", button_text="Pilih File", size=BTN_SIZE_2), 
			sg.InputText(key="document_filename", disabled=True, size=BTN_SIZE_2)
		],
		[sg.Text("Kunci Publik:")],
		[
			sg.FileBrowse(target="public_key_filename", button_text="Pilih File", size=BTN_SIZE_2), 
			sg.InputText(key="public_key_filename", disabled=True, size=BTN_SIZE_2)
		],
		[sg.Multiline(key="public_key", size=MULTILINE_SIZE)]
	], justification="center")],

	[sg.Column([[sg.Button("Verifikasi Tanda Tangan Digital", size=BTN_SIZE_1)]], justification="center")],
	[sg.Column([[sg.Button("Kembali ke Menu Utama", size=BTN_SIZE_1)]], justification="center")],
]