<?php

/* constants definitions    */
define("WP_DEBUG",false);
define("WP_DEBUG_DISPLAY",false);
define("WP_USE_EXT_MYSQL",false);
define("OBJECT","OBJECT");
define("ABSPATH",__DIR__.'/');
define('MULTISITE', $_POST["multisite"]);
define( 'WP_CONTENT_DIR', ABSPATH );
define( 'WP_CONTENT_URL', '127.0.0.1' );
define( 'WP_PLUGIN_DIR', WP_CONTENT_DIR . '/plugins' ); // Full path, no trailing slash.
define( 'WPMU_PLUGIN_DIR', WP_CONTENT_DIR . '/plugins' ); // Full path, no trailing slash.
define( 'WP_PLUGIN_URL', WP_CONTENT_URL . '/plugins' ); // Full URL, no trailing slash.
define( 'WPMU_PLUGIN_URL', WP_CONTENT_URL . '/mu-plugins' );
define( 'ARRAY_N', 'ARRAY_N' ); 
define( 'ARRAY_A', 'ARRAY_A' ); 
define( 'OBJECT_K', 'OBJECT_K' ); 
define( 'SAVEQUERIES', true );
define( 'WP_ADMIN', true );

/* variables definitions    */
$network_wide = $_POST["network_wide"];

//includes
include ABSPATH. "wp-admin/includes/class-wp-hook.php";
include ABSPATH. "wp-admin/includes/class-wp-wpdb.php";
include ABSPATH. "wp-admin/includes/class-wp-object-cache.php";

//missing global
//string array: store func name for each hook
$wp_filter = array();
$wp_current_filter = array();
$blog_id = "test.default.com";
$wpdb = new fake_wpdb('root','123','wptest','127.0.0.1');
$wp_object_cache = new WP_Object_Cache();

//function definitions
function _wp_call_all_hook( $args ) {
    global $wp_filter;
 
    $wp_filter['all']->do_all_hook( $args );
}

function apply_filters( $hook_name, $value ) {
    global $wp_filter, $wp_current_filter;
 
    $args = func_get_args();
 
    // Do 'all' actions first.
    if ( isset( $wp_filter['all'] ) ) {
        $wp_current_filter[] = $hook_name;
        _wp_call_all_hook( $args );
    }
 
    if ( ! isset( $wp_filter[ $hook_name ] ) ) {
        if ( isset( $wp_filter['all'] ) ) {
            array_pop( $wp_current_filter );
        }
 
        return $value;
    }
 
    if ( ! isset( $wp_filter['all'] ) ) {
        $wp_current_filter[] = $hook_name;
    }
 
    // Don't pass the tag name to WP_Hook.
    array_shift( $args );
 
    $filtered = $wp_filter[ $hook_name ]->apply_filters( $value, $args );
 
    array_pop( $wp_current_filter );
 
    return $filtered;
}

function do_action( $hook_name, $value ) {
    return apply_filters($hook_name, $value);
}

function add_filter( $hook_name, $callback, $priority = 10, $accepted_args = 1 ) {
    global $wp_filter;
 
    if ( ! isset( $wp_filter[ $hook_name ] ) ) {
        $wp_filter[ $hook_name ] = new WP_Hook();
    }
 
    $wp_filter[ $hook_name ]->add_filter( $hook_name, $callback, $priority, $accepted_args );
 
    return true;
}


function absint( $maybeint ) {
    return abs( (int) $maybeint );
}

function get_current_blog_id() {
    global $blog_id;
    return absint( $blog_id );
}

function wp_die( $message = '', $title = '', $args = array() ) {
    die($message);
}

function get_the_title( $post = 0 ) {
    $title = $_POST['post_title'];
    return $title;
}

function wp_check_invalid_utf8( $string, $strip = false ) {
    $string = (string) $string;
 
    if ( 0 === strlen( $string ) ) {
        return '';
    }
 
    // Store the site charset as a static to avoid multiple calls to get_option().
    static $is_utf8 = null;
    if ( ! isset( $is_utf8 ) ) {
        // $is_utf8 = in_array( get_option( 'blog_charset' ), array( 'utf8', 'utf-8', 'UTF8', 'UTF-8' ), true );
        //ca_mark: hardcode blog_charset to utf8
        $is_utf8 = in_array( 'utf8', array( 'utf8', 'utf-8', 'UTF8', 'UTF-8' ), true );
    }
    if ( ! $is_utf8 ) {
        return $string;
    }
 
    // Check for support for utf8 in the installed PCRE library once and store the result in a static.
    static $utf8_pcre = null;
    if ( ! isset( $utf8_pcre ) ) {
        // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
        $utf8_pcre = @preg_match( '/^./u', 'a' );
    }
    // We can't demand utf8 in the PCRE installation, so just return the string in those cases.
    if ( ! $utf8_pcre ) {
        return $string;
    }
 
    // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- preg_match fails when it encounters invalid UTF8 in $string.
    if ( 1 === @preg_match( '/^./us', $string ) ) {
        return $string;
    }
 
    // Attempt to strip the bad chars if requested (not recommended).
    if ( $strip && function_exists( 'iconv' ) ) {
        return iconv( 'utf-8', 'utf-8', $string );
    }
 
    return '';
}

function wp_kses_normalize_entities( $string, $context = 'html' ) {
    // Disarm all entities by converting & to &amp;
    $string = str_replace( '&', '&amp;', $string );
 
    // Change back the allowed entities in our list of allowed entities.
    if ( 'xml' === $context ) {
        $string = preg_replace_callback( '/&amp;([A-Za-z]{2,8}[0-9]{0,2});/', 'wp_kses_xml_named_entities', $string );
    } else {
        $string = preg_replace_callback( '/&amp;([A-Za-z]{2,8}[0-9]{0,2});/', 'wp_kses_named_entities', $string );
    }
    $string = preg_replace_callback( '/&amp;#(0*[0-9]{1,7});/', 'wp_kses_normalize_entities2', $string );
    $string = preg_replace_callback( '/&amp;#[Xx](0*[0-9A-Fa-f]{1,6});/', 'wp_kses_normalize_entities3', $string );
 
    return $string;
}

function _wp_specialchars( $string, $quote_style = ENT_NOQUOTES, $charset = false, $double_encode = false ) {
    $string = (string) $string;
 
    if ( 0 === strlen( $string ) ) {
        return '';
    }
 
    // Don't bother if there are no specialchars - saves some processing.
    if ( ! preg_match( '/[&<>"\']/', $string ) ) {
        return $string;
    }
 
    // Account for the previous behaviour of the function when the $quote_style is not an accepted value.
    if ( empty( $quote_style ) ) {
        $quote_style = ENT_NOQUOTES;
    } elseif ( ENT_XML1 === $quote_style ) {
        $quote_style = ENT_QUOTES | ENT_XML1;
    } elseif ( ! in_array( $quote_style, array( ENT_NOQUOTES, ENT_COMPAT, ENT_QUOTES, 'single', 'double' ), true ) ) {
        $quote_style = ENT_QUOTES;
    }
 
    // Store the site charset as a static to avoid multiple calls to wp_load_alloptions().
    if ( ! $charset ) {
        static $_charset = null;
        if ( ! isset( $_charset ) ) {
            $_charset   = 'utf8';
        }
        $charset = $_charset;
    }
 
    if ( in_array( $charset, array( 'utf8', 'utf-8', 'UTF8' ), true ) ) {
        $charset = 'UTF-8';
    }
 
    $_quote_style = $quote_style;
 
    if ( 'double' === $quote_style ) {
        $quote_style  = ENT_COMPAT;
        $_quote_style = ENT_COMPAT;
    } elseif ( 'single' === $quote_style ) {
        $quote_style = ENT_NOQUOTES;
    }
 
    if ( ! $double_encode ) {
        // Guarantee every &entity; is valid, convert &garbage; into &amp;garbage;
        // This is required for PHP < 5.4.0 because ENT_HTML401 flag is unavailable.
        $string = wp_kses_normalize_entities( $string, ( $quote_style & ENT_XML1 ) ? 'xml' : 'html' );
    }
 
    $string = htmlspecialchars( $string, $quote_style, $charset, $double_encode );
 
    // Back-compat.
    if ( 'single' === $_quote_style ) {
        $string = str_replace( "'", '&#039;', $string );
    }
 
    return $string;
}

function esc_html( $text ) {
    $safe_text = wp_check_invalid_utf8( $text );
    $safe_text = _wp_specialchars( $safe_text, ENT_QUOTES );
    /**
     * Filters a string cleaned and escaped for output in HTML.
     *
     * Text passed to esc_html() is stripped of invalid or special characters
     * before output.
     *
     * @since 2.8.0
     *
     * @param string $safe_text The text after it has been escaped.
     * @param string $text      The text prior to being escaped.
     */
    return apply_filters( 'esc_html', $safe_text, $text );
}

function wp_upload_dir( $time = null, $create_dir = true, $refresh_cache = false ){
    $res = array();
    $res['baseurl'] = "/home/ca224/";
    return $res;
}

function wp_count_posts( $type = 'post', $perm = '' ) {
        return new stdClass;
}

function get_the_ID() { // phpcs:ignore WordPress.NamingConventions.ValidFunctionName.FunctionNameInvalid
    $post = get_post();
    return ! empty( $post ) ? $post->ID : false;
}

function get_post( $post = null, $output = OBJECT, $filter = 'raw' ) {
    if ( empty( $post ) && isset( $GLOBALS['post'] ) ) {
        $post = $GLOBALS['post'];
    }
 
    if ( $post instanceof WP_Post ) {
        $_post = $post;
    } elseif ( is_object( $post ) ) {
        if ( empty( $post->filter ) ) {
            // $_post = sanitize_post( $post, 'raw' );
            $_post = new WP_Post( $post );
        } elseif ( 'raw' === $post->filter ) {
            $_post = new WP_Post( $post );
        } else {
            $_post = WP_Post::get_instance( $post->ID );
        }
    } else {
        $_post = WP_Post::get_instance( $post );
    }
 
    if ( ! $_post ) {
        return null;
    }
 
    $_post = $_post->filter( $filter );
 
    if ( ARRAY_A === $output ) {
        return $_post->to_array();
    } elseif ( ARRAY_N === $output ) {
        return array_values( $_post->to_array() );
    }
 
    return $_post;
}

function is_multisite() {
    if ( defined( 'MULTISITE' ) ) {
        return MULTISITE;
    }
 
    if ( defined( 'SUBDOMAIN_INSTALL' ) || defined( 'VHOST' ) || defined( 'SUNRISE' ) ) {
        return true;
    }
 
    return false;
}

function add_action( $hook_name, $callback, $priority = 10, $accepted_args = 1 ) {
    return add_filter( $hook_name, $callback, $priority, $accepted_args );
}

function register_activation_hook( $file, $callback ) {
    $file = plugin_basename( $file );
    add_action( 'activate_' . $file, $callback );
}

function register_deactivation_hook( $file, $callback ) {
    $file = plugin_basename( $file );
    add_action( 'deactivate_' . $file, $callback );
}

function plugin_basename( $file ) {
    global $wp_plugin_paths;
 
    // $wp_plugin_paths contains normalized paths.
    $file = wp_normalize_path( $file );
 
    arsort( $wp_plugin_paths );
 
    foreach ( $wp_plugin_paths as $dir => $realdir ) {
        if ( strpos( $file, $realdir ) === 0 ) {
            $file = $dir . substr( $file, strlen( $realdir ) );
        }
    }
 
    $plugin_dir    = wp_normalize_path( WP_PLUGIN_DIR );
    $mu_plugin_dir = wp_normalize_path( WPMU_PLUGIN_DIR );
 
    // Get relative path from plugins directory.
    $file = preg_replace( '#^' . preg_quote( $plugin_dir, '#' ) . '/|^' . preg_quote( $mu_plugin_dir, '#' ) . '/#', '', $file );
    $file = trim( $file, '/' );
    return $file;
}

function wp_normalize_path( $path ) {
    $wrapper = '';
 
    if ( wp_is_stream( $path ) ) {
        list( $wrapper, $path ) = explode( '://', $path, 2 );
 
        $wrapper .= '://';
    }
 
    // Standardise all paths to use '/'.
    $path = str_replace( '\\', '/', $path );
 
    // Replace multiple slashes down to a singular, allowing for network shares having two slashes.
    $path = preg_replace( '|(?<=.)/+|', '/', $path );
 
    // Windows paths should uppercase the drive letter.
    if ( ':' === substr( $path, 1, 1 ) ) {
        $path = ucfirst( $path );
    }
 
    return $wrapper . $path;
}

function wp_is_stream( $path ) {
    $scheme_separator = strpos( $path, '://' );
 
    if ( false === $scheme_separator ) {
        // $path isn't a stream.
        return false;
    }
 
    $stream = substr( $path, 0, $scheme_separator );
 
    return in_array( $stream, stream_get_wrappers(), true );
}

function wp_enqueue_style( $handle, $src = '', $deps = array(), $ver = false, $media = 'all' ) {
    return;
}

function plugin_dir_url( $file ) {
    return ( plugins_url( '', $file ). '/' );
}

function plugins_url( $path = '', $plugin = '' ) {
 
    $path          = wp_normalize_path( $path );
    $plugin        = wp_normalize_path( $plugin );
    $mu_plugin_dir = wp_normalize_path( WPMU_PLUGIN_DIR );
 
    if ( ! empty( $plugin ) && 0 === strpos( $plugin, $mu_plugin_dir ) ) {
        $url = WPMU_PLUGIN_URL;
    } else {
        $url = WP_PLUGIN_URL;
    }
 
    $url = set_url_scheme( $url );
 
    if ( ! empty( $plugin ) && is_string( $plugin ) ) {
        $folder = dirname( plugin_basename( $plugin ) );
        if ( '.' !== $folder ) {
            $url .= '/' . ltrim( $folder, '/' );
        }
    }
 
    if ( $path && is_string( $path ) ) {
        $url .= '/' . ltrim( $path, '/' );
    }
 
    /**
     * Filters the URL to the plugins directory.
     *
     * @since 2.8.0
     *
     * @param string $url    The complete URL to the plugins directory including scheme and path.
     * @param string $path   Path relative to the URL to the plugins directory. Blank string
     *                       if no path is specified.
     * @param string $plugin The plugin file path to be relative to. Blank string if no plugin
     *                       is specified.
     */
    return apply_filters( 'plugins_url', $url, $path, $plugin );
}

function set_url_scheme( $url, $scheme = null ) {
    $orig_scheme = $scheme;
 
    $url = trim( $url );
    if ( substr( $url, 0, 2 ) === '//' ) {
        $url = 'http:' . $url;
    }
 
    if ( 'relative' === $scheme ) {
        $url = ltrim( preg_replace( '#^\w+://[^/]*#', '', $url ) );
        if ( '' !== $url && '/' === $url[0] ) {
            $url = '/' . ltrim( $url, "/ \t\n\r\0\x0B" );
        }
    } else {
        $url = preg_replace( '#^\w+://#', $scheme . '://', $url );
    }
 
    /**
     * Filters the resulting URL after setting the scheme.
     *
     * @since 3.4.0
     *
     * @param string      $url         The complete URL including scheme and path.
     * @param string      $scheme      Scheme applied to the URL. One of 'http', 'https', or 'relative'.
     * @param string|null $orig_scheme Scheme requested for the URL. One of 'http', 'https', 'login',
     *                                 'login_post', 'admin', 'relative', 'rest', 'rpc', or null.
     */
    return apply_filters( 'set_url_scheme', $url, $scheme, $orig_scheme );
}

function current_user_can( $capability, ...$args ) {
    return true;
}

function add_menu_page( $page_title, $menu_title, $capability, $menu_slug, $function = '', $icon_url = '', $position = null ) {
    global $menu, $admin_page_hooks, $_registered_pages, $_parent_pages;
 
    $menu_slug = plugin_basename( $menu_slug );
 
    $admin_page_hooks[ $menu_slug ] = sanitize_title( $menu_title );
 
    $hookname = get_plugin_page_hookname( $menu_slug, '' );
 
    if ( ! empty( $function ) && ! empty( $hookname ) && current_user_can( $capability ) ) {
        add_action( $hookname, $function );
    }
 
    if ( empty( $icon_url ) ) {
        $icon_url   = 'dashicons-admin-generic';
        $icon_class = 'menu-icon-generic ';
    } else {
        $icon_url   = set_url_scheme( $icon_url );
        $icon_class = '';
    }
 
    $new_menu = array( $menu_title, $capability, $menu_slug, $page_title, 'menu-top ' . $icon_class . $hookname, $hookname, $icon_url );
 
    if ( null === $position ) {
        $menu[] = $new_menu;
    } elseif ( isset( $menu[ "$position" ] ) ) {
        $position            = $position + substr( base_convert( md5( $menu_slug . $menu_title ), 16, 10 ), -5 ) * 0.00001;
        $menu[ "$position" ] = $new_menu;
    } else {
        $menu[ $position ] = $new_menu;
    }
 
    $_registered_pages[ $hookname ] = true;
 
    // No parent as top level.
    $_parent_pages[ $menu_slug ] = false;
 
    return $hookname;
}

function __( $text, $domain = 'default' ) {
    return $text;
}

function _e( $text, $domain = 'default' ) {
    echo $text;
}

function sanitize_title( $title, $fallback_title = '', $context = 'save' ) {
    $raw_title = $title;

    /**
     * Filters a sanitized title string.
     *
     * @since 1.2.0
     *
     * @param string $title     Sanitized title.
     * @param string $raw_title The title prior to sanitization.
     * @param string $context   The context for which the title is being sanitized.
     */
    $title = apply_filters( 'sanitize_title', $title, $raw_title, $context );
 
    if ( '' === $title || false === $title ) {
        $title = $fallback_title;
    }
 
    return $title;
}

function get_plugin_page_hookname( $plugin_page, $parent_page ) {
    global $admin_page_hooks;
 
    $parent = get_admin_page_parent( $parent_page );
 
    $page_type = 'admin';
    if ( empty( $parent_page ) || 'admin.php' === $parent_page || isset( $admin_page_hooks[ $plugin_page ] ) ) {
        if ( isset( $admin_page_hooks[ $plugin_page ] ) ) {
            $page_type = 'toplevel';
        } elseif ( isset( $admin_page_hooks[ $parent ] ) ) {
            $page_type = $admin_page_hooks[ $parent ];
        }
    } elseif ( isset( $admin_page_hooks[ $parent ] ) ) {
        $page_type = $admin_page_hooks[ $parent ];
    }
 
    $plugin_name = preg_replace( '!\.php!', '', $plugin_page );
 
    return $page_type . '_page_' . $plugin_name;
}

function get_admin_page_parent( $parent = '' ) {
    global $parent_file, $menu, $submenu, $pagenow, $typenow,
        $plugin_page, $_wp_real_parent_file, $_wp_menu_nopriv, $_wp_submenu_nopriv;
 
    if ( ! empty( $parent ) && 'admin.php' !== $parent ) {
        if ( isset( $_wp_real_parent_file[ $parent ] ) ) {
            $parent = $_wp_real_parent_file[ $parent ];
        }
 
        return $parent;
    }
 
    if ( 'admin.php' === $pagenow && isset( $plugin_page ) ) {
        foreach ( (array) $menu as $parent_menu ) {
            if ( $parent_menu[2] === $plugin_page ) {
                $parent_file = $plugin_page;
 
                if ( isset( $_wp_real_parent_file[ $parent_file ] ) ) {
                    $parent_file = $_wp_real_parent_file[ $parent_file ];
                }
 
                return $parent_file;
            }
        }
        if ( isset( $_wp_menu_nopriv[ $plugin_page ] ) ) {
            $parent_file = $plugin_page;
 
            if ( isset( $_wp_real_parent_file[ $parent_file ] ) ) {
                    $parent_file = $_wp_real_parent_file[ $parent_file ];
            }
 
            return $parent_file;
        }
    }
 
    if ( isset( $plugin_page ) && isset( $_wp_submenu_nopriv[ $pagenow ][ $plugin_page ] ) ) {
        $parent_file = $pagenow;
 
        if ( isset( $_wp_real_parent_file[ $parent_file ] ) ) {
            $parent_file = $_wp_real_parent_file[ $parent_file ];
        }
 
        return $parent_file;
    }
 
    foreach ( array_keys( (array) $submenu ) as $parent ) {
        foreach ( $submenu[ $parent ] as $submenu_array ) {
            if ( isset( $_wp_real_parent_file[ $parent ] ) ) {
                $parent = $_wp_real_parent_file[ $parent ];
            }
 
            if ( ! empty( $typenow ) && "$pagenow?post_type=$typenow" === $submenu_array[2] ) {
                $parent_file = $parent;
                return $parent;
            } elseif ( empty( $typenow ) && $pagenow === $submenu_array[2]
                && ( empty( $parent_file ) || false === strpos( $parent_file, '?' ) )
            ) {
                $parent_file = $parent;
                return $parent;
            } elseif ( isset( $plugin_page ) && $plugin_page === $submenu_array[2] ) {
                $parent_file = $parent;
                return $parent;
            }
        }
    }
 
    if ( empty( $parent_file ) ) {
        $parent_file = '';
    }
    return '';
}

function esc_sql( $data ) {
    global $wpdb;
    return $wpdb->_escape( $data );
}

function wp_verify_nonce( $nonce, $action = -1 ) {
    return true;
}

function wp_parse_args( $args, $defaults = array() ) {
    if ( is_object( $args ) ) {
        $parsed_args = get_object_vars( $args );
    } elseif ( is_array( $args ) ) {
        $parsed_args =& $args;
    } else {
        wp_parse_str( $args, $parsed_args );
    }
 
    if ( is_array( $defaults ) && $defaults ) {
        return array_merge( $defaults, $parsed_args );
    }
    return $parsed_args;
}

function wp_parse_str( $string, &$array ) {
    parse_str( $string, $array );
 
    /**
     * Filters the array of variables derived from a parsed string.
     *
     * @since 2.3.0
     *
     * @param array $array The array populated with variables.
     */
    $array = apply_filters( 'wp_parse_str', $array );
}

function convert_to_screen( $hook_name ) {
    if ( ! class_exists( 'WP_Screen' ) ) {
        return (object) array(
            'id'   => '_invalid',
            'base' => '_are_belong_to_us',
        );
    }
 
    return WP_Screen::get( $hook_name );
}

function sanitize_key( $key ) {
    $raw_key = $key;
    $key     = strtolower( $key );
    $key     = preg_replace( '/[^a-z0-9_\-]/', '', $key );
 
    /**
     * Filters a sanitized key string.
     *
     * @since 3.0.0
     *
     * @param string $key     Sanitized key.
     * @param string $raw_key The key prior to sanitization.
     */
    return apply_filters( 'sanitize_key', $key, $raw_key );
}

function wp_debug_backtrace_summary( $ignore_class = null, $skip_frames = 0, $pretty = true ) {
    static $truncate_paths;
 
    $trace       = debug_backtrace( false );
    $caller      = array();
    $check_class = ! is_null( $ignore_class );
    $skip_frames++; // Skip this function.
 
    if ( ! isset( $truncate_paths ) ) {
        $truncate_paths = array(
            wp_normalize_path( WP_CONTENT_DIR ),
            wp_normalize_path( ABSPATH ),
        );
    }
 
    foreach ( $trace as $call ) {
        if ( $skip_frames > 0 ) {
            $skip_frames--;
        } elseif ( isset( $call['class'] ) ) {
            if ( $check_class && $ignore_class == $call['class'] ) {
                continue; // Filter out calls.
            }
 
            $caller[] = "{$call['class']}{$call['type']}{$call['function']}";
        } else {
            if ( in_array( $call['function'], array( 'do_action', 'apply_filters', 'do_action_ref_array', 'apply_filters_ref_array' ), true ) ) {
                $caller[] = "{$call['function']}('{$call['args'][0]}')";
            } elseif ( in_array( $call['function'], array( 'include', 'include_once', 'require', 'require_once' ), true ) ) {
                $filename = isset( $call['args'][0] ) ? $call['args'][0] : '';
                $caller[] = $call['function'] . "('" . str_replace( $truncate_paths, '', wp_normalize_path( $filename ) ) . "')";
            } else {
                $caller[] = $call['function'];
            }
        }
    }
    if ( $pretty ) {
        return implode( ', ', array_reverse( $caller ) );
    } else {
        return $caller;
    }
}

function has_filter( $hook_name, $callback = false ) {
    global $wp_filter;
 
    if ( ! isset( $wp_filter[ $hook_name ] ) ) {
        return false;
    }
 
    return $wp_filter[ $hook_name ]->has_filter( $hook_name, $callback );
}

function is_admin() {
    if ( isset( $GLOBALS['current_screen'] ) ) {
        return $GLOBALS['current_screen']->in_admin();
    } elseif ( defined( 'WP_ADMIN' ) ) {
        return WP_ADMIN;
    }
 
    return false;
}

function esc_url( $url, $protocols = null, $_context = 'display' ) {
    $original_url = $url;
 
    if ( '' === $url ) {
        return $url;
    }
 
    $url = str_replace( ' ', '%20', ltrim( $url ) );
    $url = preg_replace( '|[^a-z0-9-~+_.?#=!&;,/:%@$\|*\'()\[\]\\x80-\\xff]|i', '', $url );
 
    if ( '' === $url ) {
        return $url;
    }
 
    if ( 0 !== stripos( $url, 'mailto:' ) ) {
        $strip = array( '%0d', '%0a', '%0D', '%0A' );
        $url   = _deep_replace( $strip, $url );
    }
 
    $url = str_replace( ';//', '://', $url );
    /*
     * If the URL doesn't appear to contain a scheme, we presume
     * it needs http:// prepended (unless it's a relative link
     * starting with /, # or ?, or a PHP file).
     */
    if ( strpos( $url, ':' ) === false && ! in_array( $url[0], array( '/', '#', '?' ), true ) &&
        ! preg_match( '/^[a-z0-9-]+?\.php/i', $url ) ) {
        $url = 'http://' . $url;
    }
 
    // Replace ampersands and single quotes only when displaying.
    if ( 'display' === $_context ) {
        $url = wp_kses_normalize_entities( $url );
        $url = str_replace( '&amp;', '&#038;', $url );
        $url = str_replace( "'", '&#039;', $url );
    }
 
    if ( ( false !== strpos( $url, '[' ) ) || ( false !== strpos( $url, ']' ) ) ) {
 
        $parsed = wp_parse_url( $url );
        $front  = '';
 
        if ( isset( $parsed['scheme'] ) ) {
            $front .= $parsed['scheme'] . '://';
        } elseif ( '/' === $url[0] ) {
            $front .= '//';
        }
 
        if ( isset( $parsed['user'] ) ) {
            $front .= $parsed['user'];
        }
 
        if ( isset( $parsed['pass'] ) ) {
            $front .= ':' . $parsed['pass'];
        }
 
        if ( isset( $parsed['user'] ) || isset( $parsed['pass'] ) ) {
            $front .= '@';
        }
 
        if ( isset( $parsed['host'] ) ) {
            $front .= $parsed['host'];
        }
 
        if ( isset( $parsed['port'] ) ) {
            $front .= ':' . $parsed['port'];
        }
 
        $end_dirty = str_replace( $front, '', $url );
        $end_clean = str_replace( array( '[', ']' ), array( '%5B', '%5D' ), $end_dirty );
        $url       = str_replace( $end_dirty, $end_clean, $url );
 
    }
 
    if ( '/' === $url[0] ) {
        $good_protocol_url = $url;
    } else {
        if ( ! is_array( $protocols ) ) {
            $protocols = wp_allowed_protocols();
        }
        $good_protocol_url = wp_kses_bad_protocol( $url, $protocols );
        if ( strtolower( $good_protocol_url ) != strtolower( $url ) ) {
            return '';
        }
    }
 
    /**
     * Filters a string cleaned and escaped for output as a URL.
     *
     * @since 2.3.0
     *
     * @param string $good_protocol_url The cleaned URL to be returned.
     * @param string $original_url      The URL prior to cleaning.
     * @param string $_context          If 'display', replace ampersands and single quotes only.
     */
    return apply_filters( 'clean_url', $good_protocol_url, $original_url, $_context );
}

function _deep_replace( $search, $subject ) {
    $subject = (string) $subject;
 
    $count = 1;
    while ( $count ) {
        $subject = str_replace( $search, '', $subject, $count );
    }
 
    return $subject;
}

function wp_parse_url( $url, $component = -1 ) {
    $to_unset = array();
    $url      = (string) $url;
 
    if ( '//' === substr( $url, 0, 2 ) ) {
        $to_unset[] = 'scheme';
        $url        = 'placeholder:' . $url;
    } elseif ( '/' === substr( $url, 0, 1 ) ) {
        $to_unset[] = 'scheme';
        $to_unset[] = 'host';
        $url        = 'placeholder://placeholder' . $url;
    }
 
    $parts = parse_url( $url );
 
    if ( false === $parts ) {
        // Parsing failure.
        return $parts;
    }
 
    // Remove the placeholder values.
    foreach ( $to_unset as $key ) {
        unset( $parts[ $key ] );
    }
 
    return _get_component_from_parsed_url_array( $parts, $component );
}

function _get_component_from_parsed_url_array( $url_parts, $component = -1 ) {
    if ( -1 === $component ) {
        return $url_parts;
    }
 
    $key = _wp_translate_php_url_constant_to_key( $component );
    if ( false !== $key && is_array( $url_parts ) && isset( $url_parts[ $key ] ) ) {
        return $url_parts[ $key ];
    } else {
        return null;
    }
}

function _wp_translate_php_url_constant_to_key( $constant ) {
    $translation = array(
        PHP_URL_SCHEME   => 'scheme',
        PHP_URL_HOST     => 'host',
        PHP_URL_PORT     => 'port',
        PHP_URL_USER     => 'user',
        PHP_URL_PASS     => 'pass',
        PHP_URL_PATH     => 'path',
        PHP_URL_QUERY    => 'query',
        PHP_URL_FRAGMENT => 'fragment',
    );
 
    if ( isset( $translation[ $constant ] ) ) {
        return $translation[ $constant ];
    } else {
        return false;
    }
}

function wp_allowed_protocols() {
    static $protocols = array();
 
    if ( empty( $protocols ) ) {
        $protocols = array( 'http', 'https', 'ftp', 'ftps', 'mailto', 'news', 'irc', 'irc6', 'ircs', 'gopher', 'nntp', 'feed', 'telnet', 'mms', 'rtsp', 'sms', 'svn', 'tel', 'fax', 'xmpp', 'webcal', 'urn' );
    }
 
    if ( ! did_action( 'wp_loaded' ) ) {
        /**
         * Filters the list of protocols allowed in HTML attributes.
         *
         * @since 3.0.0
         *
         * @param string[] $protocols Array of allowed protocols e.g. 'http', 'ftp', 'tel', and more.
         */
        $protocols = array_unique( (array) apply_filters( 'kses_allowed_protocols', $protocols ) );
    }
 
    return $protocols;
}

function did_action( $hook_name ) {
    global $wp_actions;
 
    if ( ! isset( $wp_actions[ $hook_name ] ) ) {
        return 0;
    }
 
    return $wp_actions[ $hook_name ];
}

function plugin_dir_path( $file ) {
    return trailingslashit( dirname( $file ) );
}

function trailingslashit( $string ) {
    return untrailingslashit( $string ) . '/';
}

function untrailingslashit( $string ) {
    return rtrim( $string, '/\\' );
}

function load_plugin_textdomain( $domain, $deprecated = false, $plugin_rel_path = false ) {
    return $domain;
}

function get_option( $option, $default = false ) {
    return $default;
}

function is_main_site( $site_id = null, $network_id = null ) {
    if ( is_multisite() ) {
        return true;
    }
}

function is_serialized_string( $data ) {
    // if it isn't a string, it isn't a serialized string.
    if ( ! is_string( $data ) ) {
        return false;
    }
    $data = trim( $data );
    if ( strlen( $data ) < 4 ) {
        return false;
    } elseif ( ':' !== $data[1] ) {
        return false;
    } elseif ( ';' !== substr( $data, -1 ) ) {
        return false;
    } elseif ( 's' !== $data[0] ) {
        return false;
    } elseif ( '"' !== substr( $data, -2, 1 ) ) {
        return false;
    } else {
        return true;
    }
}

function is_serialized( $data, $strict = true ) {
    // If it isn't a string, it isn't serialized.
    if ( ! is_string( $data ) ) {
        return false;
    }
    $data = trim( $data );
    if ( 'N;' === $data ) {
        return true;
    }
    if ( strlen( $data ) < 4 ) {
        return false;
    }
    if ( ':' !== $data[1] ) {
        return false;
    }
    if ( $strict ) {
        $lastc = substr( $data, -1 );
        if ( ';' !== $lastc && '}' !== $lastc ) {
            return false;
        }
    } else {
        $semicolon = strpos( $data, ';' );
        $brace     = strpos( $data, '}' );
        // Either ; or } must exist.
        if ( false === $semicolon && false === $brace ) {
            return false;
        }
        // But neither must be in the first X characters.
        if ( false !== $semicolon && $semicolon < 3 ) {
            return false;
        }
        if ( false !== $brace && $brace < 4 ) {
            return false;
        }
    }
    $token = $data[0];
    switch ( $token ) {
        case 's':
            if ( $strict ) {
                if ( '"' !== substr( $data, -2, 1 ) ) {
                    return false;
                }
            } elseif ( false === strpos( $data, '"' ) ) {
                return false;
            }
            // Or else fall through.
        case 'a':
        case 'O':
            return (bool) preg_match( "/^{$token}:[0-9]+:/s", $data );
        case 'b':
        case 'i':
        case 'd':
            $end = $strict ? '$' : '';
            return (bool) preg_match( "/^{$token}:[0-9.E+-]+;$end/", $data );
    }
    return false;
}

function wp_get_db_schema( $scope = 'all', $blog_id = null ) {
    global $wpdb;
 
    $charset_collate = $wpdb->get_charset_collate();
 
    if ( $blog_id && $blog_id != $wpdb->blogid ) {
        $old_blog_id = $wpdb->set_blog_id( $blog_id );
    }
 
    // Engage multisite if in the middle of turning it on from network.php.
    $is_multisite = is_multisite() || ( defined( 'WP_INSTALLING_NETWORK' ) && WP_INSTALLING_NETWORK );
 
    /*
     * Indexes have a maximum size of 767 bytes. Historically, we haven't need to be concerned about that.
     * As of 4.2, however, we moved to utf8mb4, which uses 4 bytes per character. This means that an index which
     * used to have room for floor(767/3) = 255 characters, now only has room for floor(767/4) = 191 characters.
     */
    $max_index_length = 191;
 
    // Blog-specific tables.
    $blog_tables = "CREATE TABLE $wpdb->termmeta (
    meta_id bigint(20) unsigned NOT NULL auto_increment,
    term_id bigint(20) unsigned NOT NULL default '0',
    meta_key varchar(255) default NULL,
    meta_value longtext,
    PRIMARY KEY  (meta_id),
    KEY term_id (term_id),
    KEY meta_key (meta_key($max_index_length))
) $charset_collate;
CREATE TABLE $wpdb->terms (
 term_id bigint(20) unsigned NOT NULL auto_increment,
 name varchar(200) NOT NULL default '',
 slug varchar(200) NOT NULL default '',
 term_group bigint(10) NOT NULL default 0,
 PRIMARY KEY  (term_id),
 KEY slug (slug($max_index_length)),
 KEY name (name($max_index_length))
) $charset_collate;
CREATE TABLE $wpdb->term_taxonomy (
 term_taxonomy_id bigint(20) unsigned NOT NULL auto_increment,
 term_id bigint(20) unsigned NOT NULL default 0,
 taxonomy varchar(32) NOT NULL default '',
 description longtext NOT NULL,
 parent bigint(20) unsigned NOT NULL default 0,
 count bigint(20) NOT NULL default 0,
 PRIMARY KEY  (term_taxonomy_id),
 UNIQUE KEY term_id_taxonomy (term_id,taxonomy),
 KEY taxonomy (taxonomy)
) $charset_collate;
CREATE TABLE $wpdb->term_relationships (
 object_id bigint(20) unsigned NOT NULL default 0,
 term_taxonomy_id bigint(20) unsigned NOT NULL default 0,
 term_order int(11) NOT NULL default 0,
 PRIMARY KEY  (object_id,term_taxonomy_id),
 KEY term_taxonomy_id (term_taxonomy_id)
) $charset_collate;
CREATE TABLE $wpdb->commentmeta (
    meta_id bigint(20) unsigned NOT NULL auto_increment,
    comment_id bigint(20) unsigned NOT NULL default '0',
    meta_key varchar(255) default NULL,
    meta_value longtext,
    PRIMARY KEY  (meta_id),
    KEY comment_id (comment_id),
    KEY meta_key (meta_key($max_index_length))
) $charset_collate;
CREATE TABLE $wpdb->comments (
    comment_ID bigint(20) unsigned NOT NULL auto_increment,
    comment_post_ID bigint(20) unsigned NOT NULL default '0',
    comment_author tinytext NOT NULL,
    comment_author_email varchar(100) NOT NULL default '',
    comment_author_url varchar(200) NOT NULL default '',
    comment_author_IP varchar(100) NOT NULL default '',
    comment_date datetime NOT NULL default '0000-00-00 00:00:00',
    comment_date_gmt datetime NOT NULL default '0000-00-00 00:00:00',
    comment_content text NOT NULL,
    comment_karma int(11) NOT NULL default '0',
    comment_approved varchar(20) NOT NULL default '1',
    comment_agent varchar(255) NOT NULL default '',
    comment_type varchar(20) NOT NULL default 'comment',
    comment_parent bigint(20) unsigned NOT NULL default '0',
    user_id bigint(20) unsigned NOT NULL default '0',
    PRIMARY KEY  (comment_ID),
    KEY comment_post_ID (comment_post_ID),
    KEY comment_approved_date_gmt (comment_approved,comment_date_gmt),
    KEY comment_date_gmt (comment_date_gmt),
    KEY comment_parent (comment_parent),
    KEY comment_author_email (comment_author_email(10))
) $charset_collate;
CREATE TABLE $wpdb->links (
    link_id bigint(20) unsigned NOT NULL auto_increment,
    link_url varchar(255) NOT NULL default '',
    link_name varchar(255) NOT NULL default '',
    link_image varchar(255) NOT NULL default '',
    link_target varchar(25) NOT NULL default '',
    link_description varchar(255) NOT NULL default '',
    link_visible varchar(20) NOT NULL default 'Y',
    link_owner bigint(20) unsigned NOT NULL default '1',
    link_rating int(11) NOT NULL default '0',
    link_updated datetime NOT NULL default '0000-00-00 00:00:00',
    link_rel varchar(255) NOT NULL default '',
    link_notes mediumtext NOT NULL,
    link_rss varchar(255) NOT NULL default '',
    PRIMARY KEY  (link_id),
    KEY link_visible (link_visible)
) $charset_collate;
CREATE TABLE $wpdb->options (
    option_id bigint(20) unsigned NOT NULL auto_increment,
    option_name varchar(191) NOT NULL default '',
    option_value longtext NOT NULL,
    autoload varchar(20) NOT NULL default 'yes',
    PRIMARY KEY  (option_id),
    UNIQUE KEY option_name (option_name),
    KEY autoload (autoload)
) $charset_collate;
CREATE TABLE $wpdb->postmeta (
    meta_id bigint(20) unsigned NOT NULL auto_increment,
    post_id bigint(20) unsigned NOT NULL default '0',
    meta_key varchar(255) default NULL,
    meta_value longtext,
    PRIMARY KEY  (meta_id),
    KEY post_id (post_id),
    KEY meta_key (meta_key($max_index_length))
) $charset_collate;
CREATE TABLE $wpdb->posts (
    ID bigint(20) unsigned NOT NULL auto_increment,
    post_author bigint(20) unsigned NOT NULL default '0',
    post_date datetime NOT NULL default '0000-00-00 00:00:00',
    post_date_gmt datetime NOT NULL default '0000-00-00 00:00:00',
    post_content longtext NOT NULL,
    post_title text NOT NULL,
    post_excerpt text NOT NULL,
    post_status varchar(20) NOT NULL default 'publish',
    comment_status varchar(20) NOT NULL default 'open',
    ping_status varchar(20) NOT NULL default 'open',
    post_password varchar(255) NOT NULL default '',
    post_name varchar(200) NOT NULL default '',
    to_ping text NOT NULL,
    pinged text NOT NULL,
    post_modified datetime NOT NULL default '0000-00-00 00:00:00',
    post_modified_gmt datetime NOT NULL default '0000-00-00 00:00:00',
    post_content_filtered longtext NOT NULL,
    post_parent bigint(20) unsigned NOT NULL default '0',
    guid varchar(255) NOT NULL default '',
    menu_order int(11) NOT NULL default '0',
    post_type varchar(20) NOT NULL default 'post',
    post_mime_type varchar(100) NOT NULL default '',
    comment_count bigint(20) NOT NULL default '0',
    PRIMARY KEY  (ID),
    KEY post_name (post_name($max_index_length)),
    KEY type_status_date (post_type,post_status,post_date,ID),
    KEY post_parent (post_parent),
    KEY post_author (post_author)
) $charset_collate;\n";
 
    // Single site users table. The multisite flavor of the users table is handled below.
    $users_single_table = "CREATE TABLE $wpdb->users (
    ID bigint(20) unsigned NOT NULL auto_increment,
    user_login varchar(60) NOT NULL default '',
    user_pass varchar(255) NOT NULL default '',
    user_nicename varchar(50) NOT NULL default '',
    user_email varchar(100) NOT NULL default '',
    user_url varchar(100) NOT NULL default '',
    user_registered datetime NOT NULL default '0000-00-00 00:00:00',
    user_activation_key varchar(255) NOT NULL default '',
    user_status int(11) NOT NULL default '0',
    display_name varchar(250) NOT NULL default '',
    PRIMARY KEY  (ID),
    KEY user_login_key (user_login),
    KEY user_nicename (user_nicename),
    KEY user_email (user_email)
) $charset_collate;\n";
 
    // Multisite users table.
    $users_multi_table = "CREATE TABLE $wpdb->users (
    ID bigint(20) unsigned NOT NULL auto_increment,
    user_login varchar(60) NOT NULL default '',
    user_pass varchar(255) NOT NULL default '',
    user_nicename varchar(50) NOT NULL default '',
    user_email varchar(100) NOT NULL default '',
    user_url varchar(100) NOT NULL default '',
    user_registered datetime NOT NULL default '0000-00-00 00:00:00',
    user_activation_key varchar(255) NOT NULL default '',
    user_status int(11) NOT NULL default '0',
    display_name varchar(250) NOT NULL default '',
    spam tinyint(2) NOT NULL default '0',
    deleted tinyint(2) NOT NULL default '0',
    PRIMARY KEY  (ID),
    KEY user_login_key (user_login),
    KEY user_nicename (user_nicename),
    KEY user_email (user_email)
) $charset_collate;\n";
 
    // Usermeta.
    $usermeta_table = "CREATE TABLE $wpdb->usermeta (
    umeta_id bigint(20) unsigned NOT NULL auto_increment,
    user_id bigint(20) unsigned NOT NULL default '0',
    meta_key varchar(255) default NULL,
    meta_value longtext,
    PRIMARY KEY  (umeta_id),
    KEY user_id (user_id),
    KEY meta_key (meta_key($max_index_length))
) $charset_collate;\n";
 
    // Global tables.
    if ( $is_multisite ) {
        $global_tables = $users_multi_table . $usermeta_table;
    } else {
        $global_tables = $users_single_table . $usermeta_table;
    }
 
    // Multisite global tables.
    $ms_global_tables = "CREATE TABLE $wpdb->blogs (
    blog_id bigint(20) NOT NULL auto_increment,
    site_id bigint(20) NOT NULL default '0',
    domain varchar(200) NOT NULL default '',
    path varchar(100) NOT NULL default '',
    registered datetime NOT NULL default '0000-00-00 00:00:00',
    last_updated datetime NOT NULL default '0000-00-00 00:00:00',
    public tinyint(2) NOT NULL default '1',
    archived tinyint(2) NOT NULL default '0',
    mature tinyint(2) NOT NULL default '0',
    spam tinyint(2) NOT NULL default '0',
    deleted tinyint(2) NOT NULL default '0',
    lang_id int(11) NOT NULL default '0',
    PRIMARY KEY  (blog_id),
    KEY domain (domain(50),path(5)),
    KEY lang_id (lang_id)
) $charset_collate;
CREATE TABLE $wpdb->blogmeta (
    meta_id bigint(20) unsigned NOT NULL auto_increment,
    blog_id bigint(20) NOT NULL default '0',
    meta_key varchar(255) default NULL,
    meta_value longtext,
    PRIMARY KEY  (meta_id),
    KEY meta_key (meta_key($max_index_length)),
    KEY blog_id (blog_id)
) $charset_collate;
CREATE TABLE $wpdb->registration_log (
    ID bigint(20) NOT NULL auto_increment,
    email varchar(255) NOT NULL default '',
    IP varchar(30) NOT NULL default '',
    blog_id bigint(20) NOT NULL default '0',
    date_registered datetime NOT NULL default '0000-00-00 00:00:00',
    PRIMARY KEY  (ID),
    KEY IP (IP)
) $charset_collate;
CREATE TABLE $wpdb->site (
    id bigint(20) NOT NULL auto_increment,
    domain varchar(200) NOT NULL default '',
    path varchar(100) NOT NULL default '',
    PRIMARY KEY  (id),
    KEY domain (domain(140),path(51))
) $charset_collate;
CREATE TABLE $wpdb->sitemeta (
    meta_id bigint(20) NOT NULL auto_increment,
    site_id bigint(20) NOT NULL default '0',
    meta_key varchar(255) default NULL,
    meta_value longtext,
    PRIMARY KEY  (meta_id),
    KEY meta_key (meta_key($max_index_length)),
    KEY site_id (site_id)
) $charset_collate;
CREATE TABLE $wpdb->signups (
    signup_id bigint(20) NOT NULL auto_increment,
    domain varchar(200) NOT NULL default '',
    path varchar(100) NOT NULL default '',
    title longtext NOT NULL,
    user_login varchar(60) NOT NULL default '',
    user_email varchar(100) NOT NULL default '',
    registered datetime NOT NULL default '0000-00-00 00:00:00',
    activated datetime NOT NULL default '0000-00-00 00:00:00',
    active tinyint(1) NOT NULL default '0',
    activation_key varchar(50) NOT NULL default '',
    meta longtext,
    PRIMARY KEY  (signup_id),
    KEY activation_key (activation_key),
    KEY user_email (user_email),
    KEY user_login_email (user_login,user_email),
    KEY domain_path (domain(140),path(51))
) $charset_collate;";
 
    switch ( $scope ) {
        case 'blog':
            $queries = $blog_tables;
            break;
        case 'global':
            $queries = $global_tables;
            if ( $is_multisite ) {
                $queries .= $ms_global_tables;
            }
            break;
        case 'ms_global':
            $queries = $ms_global_tables;
            break;
        case 'all':
        default:
            $queries = $global_tables . $blog_tables;
            if ( $is_multisite ) {
                $queries .= $ms_global_tables;
            }
            break;
    }
 
    if ( isset( $old_blog_id ) ) {
        $wpdb->set_blog_id( $old_blog_id );
    }
 
    return $queries;
}

function register_uninstall_hook( $file, $callback ) {
    if ( is_array( $callback ) && is_object( $callback[0] ) ) {
        _doing_it_wrong( __FUNCTION__, __( 'Only a static class method or function can be used in an uninstall hook.' ), '3.1.0' );
        return;
    }
 
    /*
     * The option should not be autoloaded, because it is not needed in most
     * cases. Emphasis should be put on using the 'uninstall.php' way of
     * uninstalling the plugin.
     */
    $uninstallable_plugins = (array) get_option( 'uninstall_plugins' );
    $plugin_basename       = plugin_basename( $file );
 
    if ( ! isset( $uninstallable_plugins[ $plugin_basename ] ) || $uninstallable_plugins[ $plugin_basename ] !== $callback ) {
        $uninstallable_plugins[ $plugin_basename ] = $callback;
        update_option( 'uninstall_plugins', $uninstallable_plugins );
    }
}

function update_option( $option, $value, $autoload = null ) {
    global $wpdb;
 
    $option = trim( $option );
    if ( empty( $option ) ) {
        return false;
    }
 
    /*
     * Until a proper _deprecated_option() function can be introduced,
     * redirect requests to deprecated keys to the new, correct ones.
     */
    $deprecated_keys = array(
        'blacklist_keys'    => 'disallowed_keys',
        'comment_whitelist' => 'comment_previously_approved',
    );
 
    if ( ! wp_installing() && isset( $deprecated_keys[ $option ] ) ) {
        _deprecated_argument(
            __FUNCTION__,
            '5.5.0',
            sprintf(
                /* translators: 1: Deprecated option key, 2: New option key. */
                __( 'The "%1$s" option key has been renamed to "%2$s".' ),
                $option,
                $deprecated_keys[ $option ]
            )
        );
        return update_option( $deprecated_keys[ $option ], $value, $autoload );
    }
 
    wp_protect_special_option( $option );
 
    if ( is_object( $value ) ) {
        $value = clone $value;
    }
 
    $value     = sanitize_option( $option, $value );
    $old_value = get_option( $option );
 
    /**
     * Filters a specific option before its value is (maybe) serialized and updated.
     *
     * The dynamic portion of the hook name, `$option`, refers to the option name.
     *
     * @since 2.6.0
     * @since 4.4.0 The `$option` parameter was added.
     *
     * @param mixed  $value     The new, unserialized option value.
     * @param mixed  $old_value The old option value.
     * @param string $option    Option name.
     */
    $value = apply_filters( "pre_update_option_{$option}", $value, $old_value, $option );
 
    /**
     * Filters an option before its value is (maybe) serialized and updated.
     *
     * @since 3.9.0
     *
     * @param mixed  $value     The new, unserialized option value.
     * @param string $option    Name of the option.
     * @param mixed  $old_value The old option value.
     */
    $value = apply_filters( 'pre_update_option', $value, $option, $old_value );
 
    /*
     * If the new and old values are the same, no need to update.
     *
     * Unserialized values will be adequate in most cases. If the unserialized
     * data differs, the (maybe) serialized data is checked to avoid
     * unnecessary database calls for otherwise identical object instances.
     *
     * See https://core.trac.wordpress.org/ticket/38903
     */
    if ( $value === $old_value || maybe_serialize( $value ) === maybe_serialize( $old_value ) ) {
        return false;
    }
 
    /** This filter is documented in wp-includes/option.php */
    if ( apply_filters( "default_option_{$option}", false, $option, false ) === $old_value ) {
        // Default setting for new options is 'yes'.
        if ( null === $autoload ) {
            $autoload = 'yes';
        }
 
        return add_option( $option, $value, '', $autoload );
    }
 
    $serialized_value = maybe_serialize( $value );
 
    /**
     * Fires immediately before an option value is updated.
     *
     * @since 2.9.0
     *
     * @param string $option    Name of the option to update.
     * @param mixed  $old_value The old option value.
     * @param mixed  $value     The new option value.
     */
    do_action( 'update_option', $option, $old_value, $value );
 
    $update_args = array(
        'option_value' => $serialized_value,
    );
 
    if ( null !== $autoload ) {
        $update_args['autoload'] = ( 'no' === $autoload || false === $autoload ) ? 'no' : 'yes';
    }
 
    $result = $wpdb->update( $wpdb->options, $update_args, array( 'option_name' => $option ) );
    if ( ! $result ) {
        return false;
    }
 
    $notoptions = wp_cache_get( 'notoptions', 'options' );
 
    if ( is_array( $notoptions ) && isset( $notoptions[ $option ] ) ) {
        unset( $notoptions[ $option ] );
        wp_cache_set( 'notoptions', $notoptions, 'options' );
    }
 
    if ( ! wp_installing() ) {
        $alloptions = wp_load_alloptions( true );
        if ( isset( $alloptions[ $option ] ) ) {
            $alloptions[ $option ] = $serialized_value;
            wp_cache_set( 'alloptions', $alloptions, 'options' );
        } else {
            wp_cache_set( $option, $serialized_value, 'options' );
        }
    }
 
    /**
     * Fires after the value of a specific option has been successfully updated.
     *
     * The dynamic portion of the hook name, `$option`, refers to the option name.
     *
     * @since 2.0.1
     * @since 4.4.0 The `$option` parameter was added.
     *
     * @param mixed  $old_value The old option value.
     * @param mixed  $value     The new option value.
     * @param string $option    Option name.
     */
    do_action( "update_option_{$option}", $old_value, $value, $option );
 
    /**
     * Fires after the value of an option has been successfully updated.
     *
     * @since 2.9.0
     *
     * @param string $option    Name of the updated option.
     * @param mixed  $old_value The old option value.
     * @param mixed  $value     The new option value.
     */
    do_action( 'updated_option', $option, $old_value, $value );
 
    return true;
}

function wp_installing( $is_installing = null ) {
    static $installing = null;
 
    // Support for the `WP_INSTALLING` constant, defined before WP is loaded.
    if ( is_null( $installing ) ) {
        $installing = defined( 'WP_INSTALLING' ) && WP_INSTALLING;
    }
 
    if ( ! is_null( $is_installing ) ) {
        $old_installing = $installing;
        $installing     = $is_installing;
        return (bool) $old_installing;
    }
 
    return (bool) $installing;
}

function wp_protect_special_option( $option ) {
    if ( 'alloptions' === $option || 'notoptions' === $option ) {
        wp_die(
            sprintf(
                /* translators: %s: Option name. */
                __( '%s is a protected WP option and may not be modified' ),
                esc_html( $option )
            )
        );
    }
}

function sanitize_option( $option, $value ) {
    global $wpdb;
 
    $original_value = $value;
    $error          = '';
 
    switch ( $option ) {
        case 'admin_email':
        case 'new_admin_email':
            $value = $wpdb->strip_invalid_text_for_column( $wpdb->options, 'option_value', $value );
            if ( is_wp_error( $value ) ) {
                $error = $value->get_error_message();
            } else {
                $value = sanitize_email( $value );
                if ( ! is_email( $value ) ) {
                    $error = __( 'The email address entered did not appear to be a valid email address. Please enter a valid email address.' );
                }
            }
            break;
 
        case 'thumbnail_size_w':
        case 'thumbnail_size_h':
        case 'medium_size_w':
        case 'medium_size_h':
        case 'medium_large_size_w':
        case 'medium_large_size_h':
        case 'large_size_w':
        case 'large_size_h':
        case 'mailserver_port':
        case 'comment_max_links':
        case 'page_on_front':
        case 'page_for_posts':
        case 'rss_excerpt_length':
        case 'default_category':
        case 'default_email_category':
        case 'default_link_category':
        case 'close_comments_days_old':
        case 'comments_per_page':
        case 'thread_comments_depth':
        case 'users_can_register':
        case 'start_of_week':
        case 'site_icon':
            $value = absint( $value );
            break;
 
        case 'posts_per_page':
        case 'posts_per_rss':
            $value = (int) $value;
            if ( empty( $value ) ) {
                $value = 1;
            }
            if ( $value < -1 ) {
                $value = abs( $value );
            }
            break;
 
        case 'default_ping_status':
        case 'default_comment_status':
            // Options that if not there have 0 value but need to be something like "closed".
            if ( '0' == $value || '' === $value ) {
                $value = 'closed';
            }
            break;
 
        case 'blogdescription':
        case 'blogname':
            $value = $wpdb->strip_invalid_text_for_column( $wpdb->options, 'option_value', $value );
            if ( $value !== $original_value ) {
                $value = $wpdb->strip_invalid_text_for_column( $wpdb->options, 'option_value', wp_encode_emoji( $original_value ) );
            }
 
            if ( is_wp_error( $value ) ) {
                $error = $value->get_error_message();
            } else {
                $value = esc_html( $value );
            }
            break;
 
        case 'blog_charset':
            $value = preg_replace( '/[^a-zA-Z0-9_-]/', '', $value ); // Strips slashes.
            break;
 
        case 'blog_public':
            // This is the value if the settings checkbox is not checked on POST. Don't rely on this.
            if ( null === $value ) {
                $value = 1;
            } else {
                $value = (int) $value;
            }
            break;
 
        case 'date_format':
        case 'time_format':
        case 'mailserver_url':
        case 'mailserver_login':
        case 'mailserver_pass':
        case 'upload_path':
            $value = $wpdb->strip_invalid_text_for_column( $wpdb->options, 'option_value', $value );
            if ( is_wp_error( $value ) ) {
                $error = $value->get_error_message();
            } else {
                $value = strip_tags( $value );
                $value = wp_kses_data( $value );
            }
            break;
 
        case 'ping_sites':
            $value = explode( "\n", $value );
            $value = array_filter( array_map( 'trim', $value ) );
            $value = array_filter( array_map( 'esc_url_raw', $value ) );
            $value = implode( "\n", $value );
            break;
 
        case 'gmt_offset':
            $value = preg_replace( '/[^0-9:.-]/', '', $value ); // Strips slashes.
            break;
 
        case 'siteurl':
            $value = $wpdb->strip_invalid_text_for_column( $wpdb->options, 'option_value', $value );
            if ( is_wp_error( $value ) ) {
                $error = $value->get_error_message();
            } else {
                if ( preg_match( '#http(s?)://(.+)#i', $value ) ) {
                    $value = esc_url_raw( $value );
                } else {
                    $error = __( 'The WordPress address you entered did not appear to be a valid URL. Please enter a valid URL.' );
                }
            }
            break;
 
        case 'home':
            $value = $wpdb->strip_invalid_text_for_column( $wpdb->options, 'option_value', $value );
            if ( is_wp_error( $value ) ) {
                $error = $value->get_error_message();
            } else {
                if ( preg_match( '#http(s?)://(.+)#i', $value ) ) {
                    $value = esc_url_raw( $value );
                } else {
                    $error = __( 'The Site address you entered did not appear to be a valid URL. Please enter a valid URL.' );
                }
            }
            break;
 
        case 'WPLANG':
            $allowed = get_available_languages();
            if ( ! is_multisite() && defined( 'WPLANG' ) && '' !== WPLANG && 'en_US' !== WPLANG ) {
                $allowed[] = WPLANG;
            }
            if ( ! in_array( $value, $allowed, true ) && ! empty( $value ) ) {
                $value = get_option( $option );
            }
            break;
 
        case 'illegal_names':
            $value = $wpdb->strip_invalid_text_for_column( $wpdb->options, 'option_value', $value );
            if ( is_wp_error( $value ) ) {
                $error = $value->get_error_message();
            } else {
                if ( ! is_array( $value ) ) {
                    $value = explode( ' ', $value );
                }
 
                $value = array_values( array_filter( array_map( 'trim', $value ) ) );
 
                if ( ! $value ) {
                    $value = '';
                }
            }
            break;
 
        case 'limited_email_domains':
        case 'banned_email_domains':
            $value = $wpdb->strip_invalid_text_for_column( $wpdb->options, 'option_value', $value );
            if ( is_wp_error( $value ) ) {
                $error = $value->get_error_message();
            } else {
                if ( ! is_array( $value ) ) {
                    $value = explode( "\n", $value );
                }
 
                $domains = array_values( array_filter( array_map( 'trim', $value ) ) );
                $value   = array();
 
                foreach ( $domains as $domain ) {
                    if ( ! preg_match( '/(--|\.\.)/', $domain ) && preg_match( '|^([a-zA-Z0-9-\.])+$|', $domain ) ) {
                        $value[] = $domain;
                    }
                }
                if ( ! $value ) {
                    $value = '';
                }
            }
            break;
 
        case 'timezone_string':
            $allowed_zones = timezone_identifiers_list();
            if ( ! in_array( $value, $allowed_zones, true ) && ! empty( $value ) ) {
                $error = __( 'The timezone you have entered is not valid. Please select a valid timezone.' );
            }
            break;
 
        case 'permalink_structure':
        case 'category_base':
        case 'tag_base':
            $value = $wpdb->strip_invalid_text_for_column( $wpdb->options, 'option_value', $value );
            if ( is_wp_error( $value ) ) {
                $error = $value->get_error_message();
            } else {
                $value = esc_url_raw( $value );
                $value = str_replace( 'http://', '', $value );
            }
 
            if ( 'permalink_structure' === $option && '' !== $value && ! preg_match( '/%[^\/%]+%/', $value ) ) {
                $error = sprintf(
                    /* translators: %s: Documentation URL. */
                    __( 'A structure tag is required when using custom permalinks. <a href="%s">Learn more</a>' ),
                    __( 'https://wordpress.org/support/article/using-permalinks/#choosing-your-permalink-structure' )
                );
            }
            break;
 
        case 'default_role':
            if ( ! get_role( $value ) && get_role( 'subscriber' ) ) {
                $value = 'subscriber';
            }
            break;
 
        case 'moderation_keys':
        case 'disallowed_keys':
            $value = $wpdb->strip_invalid_text_for_column( $wpdb->options, 'option_value', $value );
            if ( is_wp_error( $value ) ) {
                $error = $value->get_error_message();
            } else {
                $value = explode( "\n", $value );
                $value = array_filter( array_map( 'trim', $value ) );
                $value = array_unique( $value );
                $value = implode( "\n", $value );
            }
            break;
    }
 
    if ( ! empty( $error ) ) {
        $value = get_option( $option );
        if ( function_exists( 'add_settings_error' ) ) {
            add_settings_error( $option, "invalid_{$option}", $error );
        }
    }
 
    /**
     * Filters an option value following sanitization.
     *
     * @since 2.3.0
     * @since 4.3.0 Added the `$original_value` parameter.
     *
     * @param string $value          The sanitized option value.
     * @param string $option         The option name.
     * @param string $original_value The original value passed to the function.
     */
    return apply_filters( "sanitize_option_{$option}", $value, $option, $original_value );
}

function maybe_serialize( $data ) {
    if ( is_array( $data ) || is_object( $data ) ) {
        return serialize( $data );
    }
 
    /*
     * Double serialization is required for backward compatibility.
     * See https://core.trac.wordpress.org/ticket/12930
     * Also the world will end. See WP 3.6.1.
     */
    if ( is_serialized( $data, false ) ) {
        return serialize( $data );
    }
 
    return $data;
}

function add_option( $option, $value = '', $deprecated = '', $autoload = 'yes' ) {
    global $wpdb;
 
    if ( ! empty( $deprecated ) ) {
        _deprecated_argument( __FUNCTION__, '2.3.0' );
    }
 
    $option = trim( $option );
    if ( empty( $option ) ) {
        return false;
    }
 
    /*
     * Until a proper _deprecated_option() function can be introduced,
     * redirect requests to deprecated keys to the new, correct ones.
     */
    $deprecated_keys = array(
        'blacklist_keys'    => 'disallowed_keys',
        'comment_whitelist' => 'comment_previously_approved',
    );
 
    if ( ! wp_installing() && isset( $deprecated_keys[ $option ] ) ) {
        _deprecated_argument(
            __FUNCTION__,
            '5.5.0',
            sprintf(
                /* translators: 1: Deprecated option key, 2: New option key. */
                __( 'The "%1$s" option key has been renamed to "%2$s".' ),
                $option,
                $deprecated_keys[ $option ]
            )
        );
        return add_option( $deprecated_keys[ $option ], $value, $deprecated, $autoload );
    }
 
    wp_protect_special_option( $option );
 
    if ( is_object( $value ) ) {
        $value = clone $value;
    }
 
    $value = sanitize_option( $option, $value );
 
    // Make sure the option doesn't already exist.
    // We can check the 'notoptions' cache before we ask for a DB query.
    $notoptions = wp_cache_get( 'notoptions', 'options' );
 
    if ( ! is_array( $notoptions ) || ! isset( $notoptions[ $option ] ) ) {
        /** This filter is documented in wp-includes/option.php */
        if ( apply_filters( "default_option_{$option}", false, $option, false ) !== get_option( $option ) ) {
            return false;
        }
    }
 
    $serialized_value = maybe_serialize( $value );
    $autoload         = ( 'no' === $autoload || false === $autoload ) ? 'no' : 'yes';
 
    /**
     * Fires before an option is added.
     *
     * @since 2.9.0
     *
     * @param string $option Name of the option to add.
     * @param mixed  $value  Value of the option.
     */
    do_action( 'add_option', $option, $value );
 
    $result = $wpdb->query( $wpdb->prepare( "INSERT INTO `$wpdb->options` (`option_name`, `option_value`, `autoload`) VALUES (%s, %s, %s) ON DUPLICATE KEY UPDATE `option_name` = VALUES(`option_name`), `option_value` = VALUES(`option_value`), `autoload` = VALUES(`autoload`)", $option, $serialized_value, $autoload ) );
    if ( ! $result ) {
        return false;
    }
 
    if ( ! wp_installing() ) {
        if ( 'yes' === $autoload ) {
            $alloptions            = wp_load_alloptions( true );
            $alloptions[ $option ] = $serialized_value;
            wp_cache_set( 'alloptions', $alloptions, 'options' );
        } else {
            wp_cache_set( $option, $serialized_value, 'options' );
        }
    }
 
    // This option exists now.
    $notoptions = wp_cache_get( 'notoptions', 'options' ); // Yes, again... we need it to be fresh.
 
    if ( is_array( $notoptions ) && isset( $notoptions[ $option ] ) ) {
        unset( $notoptions[ $option ] );
        wp_cache_set( 'notoptions', $notoptions, 'options' );
    }
 
    /**
     * Fires after a specific option has been added.
     *
     * The dynamic portion of the hook name, `$option`, refers to the option name.
     *
     * @since 2.5.0 As "add_option_{$name}"
     * @since 3.0.0
     *
     * @param string $option Name of the option to add.
     * @param mixed  $value  Value of the option.
     */
    do_action( "add_option_{$option}", $option, $value );
 
    /**
     * Fires after an option has been added.
     *
     * @since 2.9.0
     *
     * @param string $option Name of the added option.
     * @param mixed  $value  Value of the option.
     */
    do_action( 'added_option', $option, $value );
 
    return true;
}

function wp_cache_get( $key, $group = '', $force = false, &$found = null ) {
    global $wp_object_cache;
 
    return $wp_object_cache->get( $key, $group, $force, $found );
}

function esc_attr( $text ) {
    $safe_text = wp_check_invalid_utf8( $text );
    $safe_text = _wp_specialchars( $safe_text, ENT_QUOTES );
    /**
     * Filters a string cleaned and escaped for output in an HTML attribute.
     *
     * Text passed to esc_attr() is stripped of invalid or special characters
     * before output.
     *
     * @since 2.0.6
     *
     * @param string $safe_text The text after it has been escaped.
     * @param string $text      The text prior to being escaped.
     */
    return apply_filters( 'attribute_escape', $safe_text, $text );
}

function register_post_type( $post_type, $args = array() ) {
    return;
}

function add_shortcode( $tag, $callback ) {
    global $shortcode_tags;
 
    if ( '' === trim( $tag ) ) {
        _doing_it_wrong(
            __FUNCTION__,
            __( 'Invalid shortcode name: Empty name given.' ),
            '4.4.0'
        );
        return;
    }
 
    if ( 0 !== preg_match( '@[<>&/\[\]\x00-\x20=]@', $tag ) ) {
        _doing_it_wrong(
            __FUNCTION__,
            sprintf(
                /* translators: 1: Shortcode name, 2: Space-separated list of reserved characters. */
                __( 'Invalid shortcode name: %1$s. Do not use spaces or reserved characters: %2$s' ),
                $tag,
                '& / < > [ ] ='
            ),
            '4.4.0'
        );
        return;
    }
 
    $shortcode_tags[ $tag ] = $callback;
}

function is_customize_preview() {
    return true;
}

function is_wp_error( $thing ) {
    return $thing;
}

function mbstring_binary_safe_encoding( $reset = false ) {
    static $encodings  = array();
    static $overloaded = null;
 
    if ( is_null( $overloaded ) ) {
        if ( function_exists( 'mb_internal_encoding' )
            && ( (int) ini_get( 'mbstring.func_overload' ) & 2 ) // phpcs:ignore PHPCompatibility.IniDirectives.RemovedIniDirectives.mbstring_func_overloadDeprecated
        ) {
            $overloaded = true;
        } else {
            $overloaded = false;
        }
    }
 
    if ( false === $overloaded ) {
        return;
    }
 
    if ( ! $reset ) {
        $encoding = mb_internal_encoding();
        array_push( $encodings, $encoding );
        mb_internal_encoding( 'ISO-8859-1' );
    }
 
    if ( $reset && $encodings ) {
        $encoding = array_pop( $encodings );
        mb_internal_encoding( $encoding );
    }
}

function reset_mbstring_encoding() {
    mbstring_binary_safe_encoding( true );
}