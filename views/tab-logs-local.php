<?php
if (!defined('ABSPATH'))
    exit();

/**
 * @var $this Limit_Failed_Login
 */
$lockouts_total = $this->get_option('lockouts_total');
$lockouts = $this->get_option('login_lockouts');
$lockouts_now = is_array($lockouts) ? count($lockouts) : 0;

$white_list_ips = $this->get_option('whitelist');
$white_list_ips = ( is_array($white_list_ips) && !empty($white_list_ips) ) ? implode("\n", $white_list_ips) : '';

$white_list_usernames = $this->get_option('whitelist_usernames');
$white_list_usernames = ( is_array($white_list_usernames) && !empty($white_list_usernames) ) ? implode("\n", $white_list_usernames) : '';

$black_list_ips = $this->get_option('blacklist');
$black_list_ips = ( is_array($black_list_ips) && !empty($black_list_ips) ) ? implode("\n", $black_list_ips) : '';

$black_list_usernames = $this->get_option('blacklist_usernames');
$black_list_usernames = ( is_array($black_list_usernames) && !empty($black_list_usernames) ) ? implode("\n", $black_list_usernames) : '';
?>

<h3><?php echo __('Statistics', 'limit-failed-login'); ?></h3>
<form action="<?php echo esc_url($this->lfl_get_options_page_uri('logs-local')); ?>" method="post">
    <?php wp_nonce_field('limit-failed-login-options'); ?>
    <table class="form-table">
        <tr>
            <th scope="row" valign="top"><?php echo __('Total lockouts', 'limit-failed-login'); ?></th>
            <td>
                <?php if (esc_attr($lockouts_total) > 0) { ?>
                    <input class="button" name="reset_total"
                           value="<?php echo __('Reset Counter', 'limit-failed-login'); ?>"
                           type="submit"/>
                           <?php echo sprintf(_n('%d lockout since last reset', '%d lockouts since last reset', esc_attr($lockouts_total), 'limit-failed-login'), esc_attr($lockouts_total)); ?>
                           <?php
                       } else {
                           echo __('No lockouts yet', 'limit-failed-login');
                       }
                       ?>
            </td>
        </tr>
        <?php if (esc_attr($lockouts_now) > 0) { ?>
            <tr>
                <th scope="row"
                    valign="top"><?php echo __('Active lockouts', 'limit-failed-login'); ?></th>
                <td>
                    <input class="button" name="reset_current"
                           value="<?php echo __('Restore Lockouts', 'limit-failed-login'); ?>"
                           type="submit"/>
                           <?php echo sprintf(__('%d IP is currently blocked from trying to log in', 'limit-failed-login'), esc_attr($lockouts_now)); ?>
                </td>
            </tr>
        <?php } ?>
    </table>
</form>
<form action="<?php echo esc_url($this->lfl_get_options_page_uri('logs-local')); ?>" method="post">
    <?php wp_nonce_field('limit-failed-login-options'); ?>

    <table class="form-table">
        <tr>
            <th scope="row"
                valign="top"><?php echo __('Safelist', 'limit-failed-login'); ?></th>
            <td>
                <div class="field-col">
                    <p class="description"><?php _e('One IP or IP range (1.2.3.4-5.6.7.8) per line', 'limit-failed-login'); ?></p>
                    <textarea name="LFL_whitelist_ips" rows="10" cols="50"><?php echo esc_textarea($white_list_ips); ?></textarea>
                </div>
                <div class="field-col">
                    <p class="description"><?php _e('One Username per line', 'limit-failed-login'); ?></p>
                    <textarea name="LFL_whitelist_usernames" rows="10" cols="50"><?php echo esc_textarea($white_list_usernames); ?></textarea>
                </div>
            </td>
        </tr>
        <tr>
            <th scope="row"
                valign="top"><?php echo __('Blocklist', 'limit-failed-login'); ?></th>
            <td>
                <div class="field-col">
                    <p class="description"><?php _e('One IP or IP range (1.2.3.4-5.6.7.8) per line', 'limit-failed-login'); ?></p>
                    <textarea name="LFL_blacklist_ips" rows="10" cols="50"><?php echo esc_textarea($black_list_ips); ?></textarea>
                </div>
                <div class="field-col">
                    <p class="description"><?php _e('One Username per line', 'limit-failed-login'); ?></p>
                    <textarea name="LFL_blacklist_usernames" rows="10" cols="50"><?php echo esc_textarea($black_list_usernames); ?></textarea>
                </div>
            </td>
        </tr>
    </table>
    <p class="submit">
        <input class="button button-primary" name="LFLr_update_dashboard" value="<?php echo __('Save Settings', 'limit-failed-login'); ?>" type="submit"/>
    </p>
</form>
<?php
$log = $this->get_option('logged');

$log = LFL_Helpers::lfl_sorted_log_by_date($log);

$lockouts = (array) $this->get_option('lockouts');

if (is_array($log) && !empty($log)) {
    ?>
    <h3><?php echo __('Lockout log', 'limit-failed-login'); ?></h3>
    <form action="<?php echo esc_url($this->lfl_get_options_page_uri('logs-local')); ?>" method="post">
        <?php wp_nonce_field('limit-failed-login-options'); ?>
        <input type="hidden" value="true" name="clear_log"/>
        <p class="submit">
            <input class="button" name="submit" value="<?php echo __('Clear Log', 'limit-failed-login'); ?>" type="submit"/>
        </p>
    </form>

    <div class="limit-login-log">
        <table class="form-table">
            <tr>
                <th scope="col"><?php _e("Date", 'limit-failed-login'); ?></th>
                <th scope="col"><?php echo _x("IP", "Internet address", 'limit-failed-login'); ?></th>
                <th scope="col"><?php _e('Tried to log in as', 'limit-failed-login'); ?></th>
                <th scope="col"><?php _e('Gateway', 'limit-failed-login'); ?></th>
                <th>
            </tr>

            <?php foreach ($log as $date => $user_info) : ?>
                <tr>
                    <td class="limit-login-date"><?php echo date_i18n('F d, Y H:i', $date); ?></td>
                    <td class="limit-login-ip">
                        <?php echo esc_html($user_info['ip']); ?>
                    </td>
                    <td class="limit-login-max"><?php echo esc_html($user_info['username']) . ' (' . esc_html($user_info['counter']) . ' lockouts)'; ?></td>
                    <td class="limit-login-gateway"><?php echo esc_html($user_info['gateway']); ?></td>
                    <td>
                        <?php if (!empty($lockouts[$user_info['ip']]) && $lockouts[$user_info['ip']] > time()) : ?>
                            <a href="#" class="button limit-login-unlock" data-ip="<?= esc_attr($user_info['ip']) ?>" data-username="<?= esc_attr($user_info['username']) ?>">Unlock</a>
                        <?php elseif ($user_info['unlocked']): ?>
                            Unlocked
                        <?php endif ?>
                </tr>
            <?php endforeach; ?>

        </table>
    </div>
    <script>jQuery(function ($) {
            $('.limit-login-log .limit-login-unlock').click(function ()
            {
                var btn = $(this);

                if (btn.hasClass('disabled'))
                    return false;
                btn.addClass('disabled');

                $.post(ajaxurl, {
                    action: 'limit-login-unlock',
                    sec: '<?= wp_create_nonce('limit-login-unlock') ?>',
                    ip: btn.data('ip'),
                    username: btn.data('username')
                })
                        .done(function (data) {
                            if (data === true)
                                btn.fadeOut(function () {
                                    $(this).parent().text('Unlocked')
                                });
                            else
                                fail();
                        }).fail(fail);

                function fail() {
                    alert('Connection error');
                    btn.removeClass('disabled');
                }

                return false;
            });
        })</script>
    <?php
} /* if showing $log */
?>

