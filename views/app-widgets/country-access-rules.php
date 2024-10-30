<?php
if (!defined('ABSPATH'))
    exit();
?>

<div class="LFLr-block-country-wrap" style="display:none;">
    <h3><?php _e('Country Access Rules', 'limit-failed-login'); ?></h3>

    <?php
    $countries_list = LFL_Helpers::lfl_get_countries_list();
    ?>
    <div class="LFLr-block-country-section">
        <div class="LFLr-block-country-selected-wrap">
            <div class="LFLr-block-country-mode">
                <span><?php _e('these countries:', 'limit-failed-login'); ?></span>
            </div>
            <div class="LFLr-block-country-list LFLr-all-countries-selected"></div>
            <a href="#" class="LFLr-toggle-countries-list"><?php _e('Add', 'limit-failed-login'); ?></a>
        </div>
        <div class="LFLr-block-country-list LFLr-all-countries-list"></div>
    </div>
</div>
<script type="text/javascript">
    ;
    (function ($) {
        const countries = <?php echo json_encode((!empty($countries_list) ) ? $countries_list : array() ); ?>;
        $(document).ready(function () {

            LFLr.progressbar.start();

            $.post(ajaxurl, {
                action: 'app_load_country_access_rules',
                sec: '<?php echo wp_create_nonce("LFLr-action"); ?>'
            }, function (response) {

                LFLr.progressbar.stop();

                if (response.success && response.data.codes) {

                    const rule = response.data.rule || 'deny';

                    $('.LFLr-block-country-mode').prepend(`<select>
                        <option value="deny"` + (rule === 'deny' ? 'selected' : '') + `>Deny</option>
                        <option value="allow"` + (rule === 'allow' ? 'selected' : '') + `>Allow only</option>
                    </select>`);

                    let selected_countries = '';
                    let all_countries = '';

                    for (const code in countries) {

                        const is_selected = response.data.codes.includes(code);

                        if (is_selected) {
                            selected_countries += `<div class="LFLr-country" data-country="${countries[code]}"><label><input type="checkbox" value="${code}" checked>${countries[code]}</label></div>`;
                        }

                        all_countries += `<div class="LFLr-country LFLr-country-${code}"` + (is_selected ? ` style="display:none;"` : ``) + `><label><input type="checkbox" value="${code}">${countries[code]}</label></div>`;
                    }

                    $('.LFLr-all-countries-selected').html(selected_countries);
                    $('.LFLr-all-countries-list').html(all_countries);
                    $('.LFLr-block-country-wrap').show();
                }
            });

            $('.LFLr-toggle-countries-list').on('click', function (e) {
                e.preventDefault();

                $('.LFLr-all-countries-list').toggleClass('visible');
            })

            $('.LFLr-block-country-list').on('change', 'input[type="checkbox"]', function () {

                LFLr.progressbar.start();

                const $this = $(this);
                const is_checked = $this.prop('checked');
                const country_code = $this.val();

                if (!is_checked) {
                    $('.LFLr-all-countries-list').find('.LFLr-country-' + country_code).replaceWith(`<div class="LFLr-country LFLr-country-${country_code}"><label><input type="checkbox" value="${country_code}">${countries[country_code]}</label></div>`);
                    $(this).closest('.LFLr-country').remove();
                } else {

                    $this.closest('.LFLr-country').hide();

                    const $selected_countries_div = $('.LFLr-all-countries-selected');

                    $selected_countries_div.append(`<div class="LFLr-country" data-country="${countries[country_code]}"><label><input type="checkbox" value="${country_code}" checked>${countries[country_code]}</label></div>`);

                    const sort_items = $selected_countries_div.find('.LFLr-country').get();

                    sort_items.sort(function (a, b) {
                        return $(a).attr('data-country').toUpperCase().localeCompare($(b).attr('data-country').toUpperCase());
                    });

                    $.each(sort_items, function (index, item) {
                        $selected_countries_div.append(item);
                    });

                }

                $.post(ajaxurl, {
                    action: 'app_toggle_country',
                    code: country_code,
                    type: (is_checked) ? 'add' : 'remove',
                    sec: '<?php echo wp_create_nonce("LFLr-action"); ?>'
                }, function (response) {

                    LFLr.progressbar.stop();

                    if (response.success) {

                    }
                });
            })

            $('.LFLr-block-country-mode').on('change', 'select', function () {

                LFLr.progressbar.start();

                const $this = $(this);

                $.post(ajaxurl, {
                    action: 'app_country_rule',
                    rule: $this.val(),
                    sec: '<?php echo wp_create_nonce("LFLr-action"); ?>'
                }, function (response) {

                    LFLr.progressbar.stop();

                    if (response.success) {

                    }
                });
            })

        });
    })(jQuery)
</script>
