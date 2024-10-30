<?php
if (!defined('ABSPATH'))
    exit();

$active_tab = "dashboard";
$active_app = $this->get_option('active_app');
if (!empty($_GET["tab"]) && in_array(sanitize_text_field($_GET["tab"]), array('logs-local', 'logs-custom', 'settings', 'debug'))) {
    if (!$this->app && sanitize_text_field($_GET['tab']) === 'logs-custom') {
        $active_tab = 'logs-local';
    } else {
        $active_tab = sanitize_text_field($_GET["tab"]);
    }
}
?>

<div class="wrap limit-login-page-settings">
    <h2><?php echo __('Limit Failed Logins', 'limit-failed-login'); ?></h2>

    <h2 class="nav-tab-wrapper">
        <a href="<?php echo esc_url($this->lfl_get_options_page_uri('dashboard')); ?>" class="nav-tab <?php if (esc_attr($active_tab) == 'dashboard') { echo 'nav-tab-active'; } ?> "><?php _e('Dashboard', 'limit-failed-login'); ?></a>
        <a href="<?php echo esc_url($this->lfl_get_options_page_uri('settings')); ?>" class="nav-tab <?php if (esc_attr($active_tab) == 'settings') { echo 'nav-tab-active'; } ?> "><?php _e('Settings', 'limit-failed-login'); ?></a>
        <?php if ($active_app === 'custom') : ?>
            <a href="<?php echo esc_url($this->lfl_get_options_page_uri('logs-custom')); ?>" class="nav-tab <?php if (esc_attr($active_tab) == 'logs-custom') { echo 'nav-tab-active'; } ?> "><?php _e('Logs', 'limit-failed-login'); ?></a>
        <?php else : ?>
            <a href="<?php echo esc_url($this->lfl_get_options_page_uri('logs-local')); ?>" class="nav-tab <?php if (esc_attr($active_tab) == 'logs-local') { echo 'nav-tab-active'; }?> "><?php _e('Logs', 'limit-failed-login'); ?></a>
        <?php endif; ?>
        <a href="<?php echo esc_url($this->lfl_get_options_page_uri('debug')); ?>" class="nav-tab <?php if (esc_attr($active_tab) == 'debug') { echo 'nav-tab-active'; } ?>"><?php _e('Debug', 'limit-failed-login'); ?></a>
        <?php if (esc_attr($active_tab) == 'logs-custom') : ?>
            <a class="LFLr-failover-link" href="<?php echo esc_url($this->lfl_get_options_page_uri('logs-local')); ?>"><?php _e('Failover', 'limit-failed-login'); ?></a>
        <?php endif; ?>
    </h2>

    <?php include_once(LFL_PLUGIN_DIR . 'views/tab-' . esc_attr($active_tab) . '.php'); ?>
</div>

