<?php
if (!defined('ABSPATH'))
    exit();
?>

<div class="LFLr-app-acl-rules">
    <div class="app-rules-col">
        <h3><?php _e('Login Access Rules', 'limit-failed-login'); ?></h3>
        <div class="LFLr-table-scroll-wrap LFLr-app-login-access-rules-infinity-scroll">
            <table class="form-table LFLr-app-login-access-rules-table">
                <tr>
                    <th scope="col"><?php _e('Pattern', 'limit-failed-login'); ?></th>
                    <th scope="col"><?php _e('Rule', 'limit-failed-login'); ?></th>
                    <th class="LFLr-app-acl-action-col" scope="col"><?php _e('Action', 'limit-failed-login'); ?></th>
                </tr>
                <tr>
                    <td><input class="regular-text LFLr-app-acl-pattern" type="text" placeholder="<?php esc_attr_e('Pattern', 'limit-failed-login'); ?>"></td>
                    <td>
                        <select class="LFLr-app-acl-rule">
                            <option value="deny" selected><?php esc_html_e('Deny', 'limit-failed-login'); ?></option>
                            <option value="allow"><?php esc_html_e('Allow', 'limit-failed-login'); ?></option>
                            <option value="pass"><?php esc_html_e('Pass', 'limit-failed-login'); ?></option>
                        </select>
                    </td>
                    <td class="LFLr-app-acl-action-col"><button class="button LFLr-app-acl-add-rule" data-type="login"><?php _e('Add', 'limit-failed-login'); ?></button></td>
                </tr>
            </table>
        </div>
    </div>
    <div class="app-rules-col">
        <h3><?php _e('IP Access Rules', 'limit-failed-login'); ?></h3>
        <div class="LFLr-table-scroll-wrap LFLr-app-ip-access-rules-infinity-scroll">
            <table class="form-table LFLr-app-ip-access-rules-table">
                <tr>
                    <th scope="col"><?php _e('Pattern', 'limit-failed-login'); ?></th>
                    <th scope="col"><?php _e('Rule', 'limit-failed-login'); ?></th>
                    <th class="LFLr-app-acl-action-col" scope="col"><?php _e('Action', 'limit-failed-login'); ?></th>
                </tr>
                <tr>
                    <td><input class="regular-text LFLr-app-acl-pattern" type="text" placeholder="<?php esc_attr_e('Pattern', 'limit-failed-login'); ?>"></td>
                    <td>
                        <select class="LFLr-app-acl-rule">
                            <option value="deny" selected><?php esc_html_e('Deny', 'limit-failed-login'); ?></option>
                            <option value="allow"><?php esc_html_e('Allow', 'limit-failed-login'); ?></option>
                            <option value="pass"><?php esc_html_e('Pass', 'limit-failed-login'); ?></option>
                        </select>
                    </td>
                    <td class="LFLr-app-acl-action-col"><button class="button LFLr-app-acl-add-rule" data-type="ip"><?php _e('Add', 'limit-failed-login'); ?></button></td>
                </tr>
            </table>
        </div>
    </div>

    <script type="text/javascript">
        ;
        (function ($) {

            $(document).ready(function () {

                var $app_acl_rules = $('.LFLr-app-acl-rules'),
                        $infinity_box1 = $('.LFLr-app-login-access-rules-infinity-scroll'),
                        $infinity_box2 = $('.LFLr-app-ip-access-rules-infinity-scroll'),
                        loading_data1 = false,
                        loading_data2 = false,
                        page_offset1 = '',
                        page_offset2 = '',
                        page_limit = 10;

                $infinity_box1.on('scroll', function () {
                    if (!loading_data1 && $infinity_box1.get(0).scrollTop + $infinity_box1.get(0).clientHeight >= $infinity_box1.get(0).scrollHeight - 1) {
                        load_rules_data('login');
                    }
                });
                $infinity_box2.on('scroll', function () {
                    if (!loading_data2 && $infinity_box2.get(0).scrollTop + $infinity_box2.get(0).clientHeight >= $infinity_box2.get(0).scrollHeight - 1) {
                        load_rules_data('ip');
                    }
                });

                load_rules_data('login');
                load_rules_data('ip');

                $app_acl_rules
                        .on('click', '.LFLr-app-acl-remove', function (e) {
                            e.preventDefault();

                            if (!confirm('Are you sure?')) {
                                return false;
                            }

                            var $this = $(this),
                                    pattern = $this.data('pattern');

                            if (!pattern) {

                                console.log('Wrong pattern');
                                return false;
                            }

                            LFLr.progressbar.start();

                            $.post(ajaxurl, {
                                action: 'app_acl_remove_rule',
                                pattern: pattern,
                                type: $this.data('type'),
                                sec: '<?php echo esc_js(wp_create_nonce("LFLr-action")); ?>'
                            }, function (response) {

                                LFLr.progressbar.stop();

                                if (response.success) {

                                    $this.closest('tr').fadeOut(300, function () {
                                        $this.closest('tr').remove();
                                    })

                                }

                            });

                        })
                        .on('click', '.LFLr-app-acl-add-rule', function (e) {
                            e.preventDefault();

                            var $this = $(this),
                                    pattern = $this.closest('tr').find('.LFLr-app-acl-pattern').val().trim(),
                                    rule = $this.closest('tr').find('.LFLr-app-acl-rule').val(),
                                    type = $this.data('type');

                            if (!pattern) {

                                alert('Pattern can\'t be empty!');
                                return false;
                            }

                            var row_exist = {};
                            $this.closest('table').find('.rule-pattern').each(function (i, el) {
                                var res = el.innerText.localeCompare(pattern);
                                if (res === 0) {
                                    row_exist = $(el).closest('tr');
                                }
                            });

                            if (row_exist.length) {

                                $this.closest('tr').find('.LFLr-app-acl-pattern').val('');
                                row_exist.remove();
                            }

                            LFLr.progressbar.start();

                            $.post(ajaxurl, {
                                action: 'app_acl_add_rule',
                                pattern: pattern,
                                rule: rule,
                                type: type,
                                sec: '<?php echo esc_js(wp_create_nonce("LFLr-action")); ?>'
                            }, function (response) {

                                LFLr.progressbar.stop();

                                if (response.success) {

                                    $this.closest('table').find('.empty-row').remove();

                                    $this.closest('tr').after('<tr class="LFLr-app-rule-' + rule + '">' +
                                            '<td class="rule-pattern">' + pattern + '</td>' +
                                            '<td>' + rule + ((type === 'ip') ? '<span class="origin">manual</span>' : '') + '</td>' +
                                            '<td class="LFLr-app-acl-action-col" scope="col"><button class="button LFLr-app-acl-remove" data-type="' + type + '" data-pattern="' + pattern + '"><span class="dashicons dashicons-no"></span></button></td>' +
                                            '</tr>');

                                }

                            });

                        });

                function load_rules_data(type) {

                    if (type === 'login') {

                        if (page_offset1 === false) {
                            return;
                        }

                        loading_data1 = true;
                    } else if (type === 'ip') {

                        if (page_offset2 === false) {
                            return;
                        }

                        loading_data2 = true;
                    }

                    LFLr.progressbar.start();

                    $.post(ajaxurl, {
                        action: 'app_load_acl_rules',
                        type: type,
                        limit: page_limit,
                        offset: (type === 'login') ? page_offset1 : page_offset2,
                        sec: '<?php echo wp_create_nonce("LFLr-action"); ?>'
                    }, function (response) {

                        LFLr.progressbar.stop();

                        if (response.success) {

                            $('.LFLr-app-' + type + '-access-rules-table').append(response.data.html);

                            if (type === 'login') {

                                if (response.data.offset) {
                                    page_offset1 = response.data.offset;
                                } else {
                                    page_offset1 = false;
                                }

                            } else if (type === 'ip') {

                                if (response.data.offset) {
                                    page_offset2 = response.data.offset;
                                } else {
                                    page_offset2 = false;
                                }
                            }
                        }

                        if (type === 'login') {

                            loading_data1 = false;
                        } else if (type === 'ip') {

                            loading_data2 = false;
                        }
                    });
                }

            });

        })(jQuery);
    </script>
</div>
