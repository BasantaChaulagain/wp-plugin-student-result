<?php

//includes
include ABSPATH. "wp-admin/includes/class-wp-hook.php";
include ABSPATH. "wp-admin/includes/class-wp-wpdb.php";

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

//missing global
//string array: store func name for each hook
$wp_filter = array();
$wp_current_filter = array();
$blog_id = "test.default.com";
$wpdb = new fake_wpdb('root','123','wptest','127.0.0.1');

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
