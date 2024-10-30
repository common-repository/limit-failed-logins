<?php
if (!defined('ABSPATH'))
    exit();

/**
 * @var $this Limit_Failed_Login
 */
?>
<div class="limit-login-app-dashboard">
    <?php include_once( LFL_PLUGIN_DIR . 'views/app-widgets/active-lockouts.php'); ?>
    <?php include_once( LFL_PLUGIN_DIR . 'views/app-widgets/event-log.php'); ?>
    <?php include_once( LFL_PLUGIN_DIR . 'views/app-widgets/country-access-rules.php'); ?>
    <?php include_once( LFL_PLUGIN_DIR . 'views/app-widgets/acl-rules.php'); ?>
</div>