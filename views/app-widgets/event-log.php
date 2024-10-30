<?php
if (!defined('ABSPATH'))
    exit();
?>
<?php
$app_config = $this->lfl_get_custom_app_config();
?>
<div class="LFLr-table-header">
    <h3><?php _e('Event Log', 'limit-failed-login'); ?></h3>
</div>

<div class="LFLr-table-scroll-wrap LFLr-app-log-infinity-scroll">
    <table class="form-table LFLr-table-app-log">
        <tr>
            <th scope="col"><?php _e("Time", 'limit-failed-login'); ?></th>
            <th scope="col"><?php _e("IP", 'limit-failed-login'); ?></th>
            <th scope="col"><?php _e("Gateway", 'limit-failed-login'); ?></th>
            <th scope="col"><?php _e("Login", 'limit-failed-login'); ?></th>
            <th scope="col"><?php _e("Rule", 'limit-failed-login'); ?></th>
            <th scope="col"><?php _e("Reason", 'limit-failed-login'); ?></th>
            <th scope="col"><?php _e("Pattern", 'limit-failed-login'); ?></th>
            <th scope="col"><?php _e("Attempts Left", 'limit-failed-login'); ?></th>
            <th scope="col"><?php _e("Lockout Duration", 'limit-failed-login'); ?></th>
            <th scope="col"><?php _e("Actions", 'limit-failed-login'); ?></th>
        </tr>
    </table>
</div>
<script type="text/javascript">
    ;
    (function ($) {

        $(document).ready(function () {

            var $log_table = $('.LFLr-table-app-log'),
                    $infinity_box = $('.LFLr-app-log-infinity-scroll'),
                    loading_data = false,
                    page_offset = '',
                    page_limit = 10,
                    total_loaded = 0;

            $infinity_box.on('scroll', function () {
                if (!loading_data && $infinity_box.get(0).scrollTop + $infinity_box.get(0).clientHeight >= $infinity_box.get(0).scrollHeight - 1) {
                    load_log_data();
                }
            });

            load_log_data();

            $log_table.on('click', '.js-app-log-action', function (e) {
                e.preventDefault();

                var $this = $(this),
                        method = $this.data('method'),
                        params = $this.data('params');

                if (!confirm('Are you sure?'))
                    return;

                LFLr.progressbar.start();

                $.post(ajaxurl, {
                    action: 'app_log_action',
                    method: method,
                    params: params,
                    sec: '<?php echo esc_js(wp_create_nonce("LFLr-action")); ?>'
                }, function (response) {

                    LFLr.progressbar.stop();

                    if (response.success) {

                        if (method === 'lockout/delete') {
                            $('.LFLr-table-app-lockouts').trigger('LFLr:refresh');
                        }
                    }

                });
            });

            function load_log_data() {

                if (page_offset === false) {
                    return;
                }

                LFLr.progressbar.start();
                loading_data = true;

                $.post(ajaxurl, {
                    action: 'app_load_log',
                    offset: page_offset,
                    limit: page_limit,
                    sec: '<?php echo wp_create_nonce("LFLr-action"); ?>'
                }, function (response) {

                    LFLr.progressbar.stop();

                    if (response.success) {

                        $log_table.append(response.data.html);

                        total_loaded += response.data.total_items;

                        if (response.data.offset) {
                            page_offset = response.data.offset;

                            if (response.data.total_items < page_limit && total_loaded < page_limit) {
                                console.log('extra load');
                                load_log_data();
                            }

                        } else {
                            page_offset = false;
                        }

                        loading_data = false;
                    }

                });

            }
        });

    })(jQuery);
</script>