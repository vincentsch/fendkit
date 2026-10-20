<?php
defined( 'ABSPATH' ) || exit;

class Acme_Booking_Form {
	public function render() {
		return '<form class="acme-booking"><input name="name"><input name="date"></form>';
	}
}
