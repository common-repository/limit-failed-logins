<?php

if (!defined('ABSPATH'))
    exit();

/**
 * Class LFL_Shortcodes
 */
class LFL_Shortcodes {

    /**
     * Register all shortcodes
     */
    public function register() {

        add_shortcode('LFLr-link', array($this, 'LFLr_link_callback'));
    }

    /**
     * [LFLr-link url="" text=""] callback
     *
     * @param $atts
     * @return string
     */
    public function LFLr_link_callback($atts) {

        $atts = shortcode_atts(array(
            'url' => '#',
            'text' => 'Link'
                ), $atts);

        return '<a href="' . esc_attr($atts['url']) . '" target="_blank">' . esc_html($atts['text']) . '</a>';
    }

}

(new LFL_Shortcodes())->register();
