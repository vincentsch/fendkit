<?php
/**
 * Plugin Name:       Acme Booking
 * Plugin URI:        https://example.com/acme-booking
 * Description:       Appointment booking forms for small businesses. Example plugin for Fendkit tests.
 * Version:           2.3.1
 * Requires at least: 6.4
 * Requires PHP:      8.1
 * Author:            Acme Plugins GmbH
 * Author URI:        https://example.com
 * License:           GPL-2.0-or-later
 * Text Domain:       acme-booking
 */

defined( 'ABSPATH' ) || exit;

require_once __DIR__ . '/vendor/autoload.php';
require_once __DIR__ . '/includes/class-booking-form.php';

add_action( 'wp_enqueue_scripts', function () {
	wp_enqueue_script( 'moment', plugins_url( 'assets/js/vendor/moment.min.js', __FILE__ ), array(), '2.24.0', true );
	wp_enqueue_script( 'select2', plugins_url( 'assets/js/vendor/select2.min.js', __FILE__ ), array( 'jquery' ), '4.0.5', true );
	wp_enqueue_script( 'jquery-validate', plugins_url( 'assets/js/vendor/jquery.validate.min.js', __FILE__ ), array( 'jquery' ), '1.19.1', true );
} );
