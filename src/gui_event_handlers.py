'''
Event Handlers
'''

def handle_event_keygen(window, values, ecc):
	ecc.generate_keys()
	private_key_string = str(ecc.get_key_pri_a()) + " " + str(ecc.get_key_pri_b())
	public_key_a = ecc.get_key_point_a()
	public_key_b = ecc.get_key_point_b()
	public_key_string = str(public_key_a[0]) + " " + str(public_key_a[1]) + " " + str(public_key_b[0]) + " " + str(public_key_b[1])
	window["private_key"].update(private_key_string)
	window["public_key"].update(public_key_string)