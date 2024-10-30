<?php
if (!defined('ABSPATH'))
    exit();

/**
 * @var $this Limit_Failed_Login
 */
$gdpr = $this->get_option('gdpr');
$gdpr_message = $this->get_option('gdpr_message');

$v = explode(',', $this->get_option('lockout_notify'));
$email_checked = in_array('email', $v) ? ' checked ' : '';

$show_top_level_menu_item = $this->get_option('show_top_level_menu_item');

$admin_notify_email = $this->get_option('admin_notify_email');
$admin_email_placeholder = (!is_multisite()) ? get_option('admin_email') : get_site_option('admin_email');

$trusted_ip_origins = $this->get_option('trusted_ip_origins');
$trusted_ip_origins = ( is_array($trusted_ip_origins) && !empty($trusted_ip_origins) ) ? implode(", ", $trusted_ip_origins) : 'REMOTE_ADDR';

$active_app = $this->get_option('active_app');
$app_setup_code = $this->get_option('app_setup_code');
$active_app_config = $this->lfl_get_custom_app_config();
?>
<?php if (isset($_GET['activated'])) : ?>
    <div class="LFLr-app-notice success">
        <p><?php echo esc_attr($active_app_config['messages']['setup_success']); ?></p>
    </div>
<?php endif; ?>

<h3><?php echo __('General Settings', 'limit-failed-login'); ?></h3>
<form action="<?php echo esc_url($this->lfl_get_options_page_uri('settings')); ?>" method="post">

    <?php wp_nonce_field('limit-failed-login-options'); ?>

    <?php if (is_network_admin()): ?>
        <input type="checkbox" name="allow_local_options" <?php echo $this->get_option('allow_local_options') ? 'checked' : '' ?> value="1"/> <?php esc_html_e('Let network sites use their own settings', 'limit-failed-login'); ?>
        <p class="description"><?php esc_html_e('If disabled, the global settings will be forcibly applied to the entire network.') ?></p>
    <?php elseif ($this->network_mode): ?>
        <input type="checkbox" name="use_global_options" <?php echo esc_attr($this->get_option('use_local_options')) ? '' : 'checked' ?> value="1" class="use_global_options"/> <?php echo __('Use global settings', 'limit-failed-login'); ?><br/>
        <script>
            jQuery(function ($) {
                var first = true;
                $('.use_global_options').change(function () {
                    var form = $(this).siblings('table');
                    form.stop();

                    if (this.checked)
                        first ? form.hide() : form.fadeOut();
                    else
                        first ? form.show() : form.fadeIn();

                    first = false;
                }).change();
            });
        </script>
    <?php endif ?>

    <table class="form-table">
        <tr>
            <th scope="row"
                valign="top"><?php echo __('Notify on lockout', 'limit-failed-login'); ?></th>
            <td>
                <input type="checkbox" name="lockout_notify_email" <?php echo $email_checked; ?>
                       value="email"/> <?php echo __('Email to', 'limit-failed-login'); ?>
                <input type="email" name="admin_notify_email"
                       value="<?php echo esc_attr($admin_notify_email) ?>"
                       placeholder="<?php echo esc_attr($admin_email_placeholder); ?>"/> <?php echo __('after', 'limit-failed-login'); ?>
                <input type="text" size="3" maxlength="4"
                       value="<?php echo( esc_attr($this->get_option('notify_email_after')) ); ?>"
                       name="email_after"/> <?php echo __('lockouts', 'limit-failed-login'); ?>
            </td>
        </tr>

        <tr>
            <th scope="row"
                valign="top"><?php echo __('Show top-level menu item', 'limit-failed-login'); ?></th>
            <td>
                <input type="checkbox" name="show_top_level_menu_item" <?php checked(esc_attr($show_top_level_menu_item)); ?>> <?php _e('(Reload the page to see the changes)', 'limit-failed-login') ?>
            </td>
        </tr>
    </table>

    <div id="LFLr-apps-accordions" class="LFLr-accordions">
        <div>
            <table class="form-table">
                <tr>
                    <th scope="row" valign="top"><?php echo __('Lockout', 'limit-failed-login'); ?></th>
                    <td>

                        <input type="text" size="3" maxlength="4"
                               value="<?php echo( esc_attr($this->get_option('allowed_retries')) ); ?>"
                               name="allowed_retries"/> <?php echo __('allowed retries', 'limit-failed-login'); ?>
                        <br/>
                        <input type="text" size="3" maxlength="4"
                               value="<?php echo( esc_attr($this->get_option('lockout_duration')) / 60 ); ?>"
                               name="lockout_duration"/> <?php echo __('minutes lockout', 'limit-failed-login'); ?>
                        <br/>
                        <input type="text" size="3" maxlength="4"
                               value="<?php echo( esc_attr($this->get_option('allowed_lockouts')) ); ?>"
                               name="allowed_lockouts"/> <?php echo __('lockouts increase lockout time to', 'limit-failed-login'); ?>
                        <input type="text" size="3" maxlength="4"
                               value="<?php echo( esc_attr($this->get_option('long_duration')) / 3600 ); ?>"
                               name="long_duration"/> <?php echo __('hours', 'limit-failed-login'); ?> <br/>
                        <input type="text" size="3" maxlength="4"
                               value="<?php echo( esc_attr($this->get_option('valid_duration')) / 3600 ); ?>"
                               name="valid_duration"/> <?php echo __('hours until retries are reset', 'limit-failed-login'); ?>
                    </td>
                </tr>
                <tr>
                    <th scope="row"
                        valign="top"><?php echo __('Trusted IP Origins', 'limit-failed-login'); ?></th>
                    <td>
                        <div class="field-col">
                            <input type="text" class="regular-text" style="width: 100%;max-width: 431px;" name="LFL_trusted_ip_origins" value="<?php echo esc_attr($trusted_ip_origins); ?>">
                            <p class="description"><?php _e('Specify the origins you trust in order of priority, separated by commas. We strongly recommend that you <b>do not</b> use anything other than REMOTE_ADDR since other origins can be easily faked. Examples: HTTP_X_FORWARDED_FOR, HTTP_CF_CONNECTING_IP, HTTP_X_SUCURI_CLIENTIP', 'limit-failed-login'); ?></p>
                        </div>
                    </td>
                </tr>
            </table>
        </div>
    </div>

    <script type="text/javascript">
        (function ($) {
            $(document).ready(function () {
                $("#LFLr-apps-accordion").accordion({
                    heightStyle: "content",
                    active: <?php echo ( $active_app === 'local' ) ? 0 : 1; ?>
                });

                var $app_ajax_spinner = $('.LFLr-app-ajax-spinner'),
                        $app_ajax_msg = $('.LFLr-app-ajax-msg'),
                        $app_config_field = $('#limit-login-app-config');

                if ($app_config_field.val()) {
                    var pretty = JSON.stringify(JSON.parse($app_config_field.val()), undefined, 2);
                    $app_config_field.val(pretty);
                }

                $('#limit-login-app-setup').on('click', function (e) {
                    e.preventDefault();

                    $app_ajax_msg.text('').removeClass('success error');
                    $app_ajax_spinner.css('visibility', 'visible');

                    var setup_code = $('#limit-login-app-setup-code').val();

                    $.post(ajaxurl, {
                        action: 'app_setup',
                        code: setup_code,
                        sec: '<?php echo esc_js(wp_create_nonce("LFLr-action")); ?>'
                    }, function (response) {

                        if (!response.success) {

                            $app_ajax_msg.addClass('error');
                        } else {

                            $app_ajax_msg.addClass('success');

                            setTimeout(function () {

                                window.location = window.location + '&activated';

                            }, 1000);
                        }

                        if (!response.success && response.data.msg) {

                            $app_ajax_msg.text(response.data.msg);
                        }

                        $app_ajax_spinner.css('visibility', 'hidden');

                        setTimeout(function () {

                            $app_ajax_msg.text('').removeClass('success error');

                        }, 5000);
                    });

                });

                $('.LFLr-show-app-fields').on('click', function (e) {
                    e.preventDefault();

                    $('.LFLr-app-field').toggleClass('active');

                });

                $('.LFLr-upgrade-to-cloud').on('click', function (e) {
                    e.preventDefault();

                    $("#ui-id-3").click();

                    $([document.documentElement, document.body]).animate({
                        scrollTop: $("#LFLr-apps-accordion").offset().top
                    }, 500);
                });

            });

        })(jQuery);
    </script>

    <p class="submit">
        <input class="button button-primary" name="LFLr_update_settings" value="<?php echo __('Save Settings', 'limit-failed-login'); ?>" type="submit"/>
    </p>
</form>

