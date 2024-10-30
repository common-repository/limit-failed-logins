<?php
if (!defined('ABSPATH'))
    exit();

$active_app = $this->get_option('active_app');
$active_app = ($active_app === 'custom' && $this->app) ? 'custom' : 'local';

$retries_chart_title = '';
$retries_chart_desc = '';
$retries_chart_color = '';
$retries_chart_show_actions = false;

$api_stats = false;
$retries_count = 0;
if (esc_attr($active_app) === 'local') {

    $retries_stats = $this->get_option('retries_stats');

    if ($retries_stats) {
        if (array_key_exists(date_i18n('Y-m-d'), $retries_stats)) {
            $retries_count = (int) $retries_stats[date_i18n('Y-m-d')];
        }
    }

    if ($retries_count === 0) {

        $retries_chart_title = __('Hooray! Zero failed login attempts today', 'limit-failed-login');
        $retries_chart_color = '#66CC66';
    } else if ($retries_count < 100) {

        $retries_chart_title = sprintf(_n('%d failed login attempt ', '%d failed login attempts ', esc_attr($retries_count), 'limit-failed-login'), esc_attr($retries_count));
        $retries_chart_title .= __('today', 'limit-failed-login');
        $retries_chart_desc = __('Your site might have been discovered by hackers', 'limit-failed-login');
        $retries_chart_color = '#FFCC66';
    } else {

        $retries_chart_title = __('Warning: More than 100 failed login attempts today', 'limit-failed-login');
        $retries_chart_desc = __('Your site is likely under a brute-force attack', 'limit-failed-login');
        $retries_chart_color = '#FF6633';
        $retries_chart_show_actions = true;
    }
} else {

    $api_stats = $this->app->stats();

    if ($api_stats && !empty($api_stats['attempts']['count'])) {

        $retries_count = (int) end($api_stats['attempts']['count']);
    }

    $retries_chart_title = __('Failed Login Attempts Today', 'limit-failed-login');
    $retries_chart_desc = __('All failed login attempts have been neutralized in the cloud', 'limit-failed-login');
    $retries_chart_color = '#66CC66';
}
?>

<div id="LFLr-dashboard-page">
    <div class="dashboard-header">
        <h1><?php _e('Limit Failed Logins Dashboard', 'limit-failed-login'); ?></h1>
    </div>
    <div class="dashboard-section-1 <?php echo esc_attr($active_app); ?>">
        <div class="info-box-1">
            <div class="section-title"><?php _e('Failed Login Attempts', 'limit-failed-login'); ?></div>
            <div class="section-content">
                <div class="chart">
                    <canvas id="LFLr-attack-velocity-chart"></canvas>
                    <span class="LFLr-retries-count"><?php echo esc_html($retries_count); ?></span>
                </div>
                <script type="text/javascript">
                    (function() {

                        var ctx = document.getElementById('LFLr-attack-velocity-chart').getContext('2d');
                        var LFLr_retries_chart = new Chart(ctx, {
                            type: 'doughnut',
                            data: {
                                // labels: ['Success', 'Warning', 'Warning', 'Fail'],
                                datasets: [{
                                        data: [1],
                                        value: <?php echo esc_js($retries_count); ?>,
                                        backgroundColor: ['<?php echo esc_js($retries_chart_color); ?>'],
                                        borderWidth: [0]
                                    }]
                            },
                            options: {
                                responsive: true,
                                cutoutPercentage: 70,
                                title: {
                                    display: false,
                                    // text: 'Local Attack Velocity'
                                },
                                tooltips: {
                                    enabled: false
                                },
                                layout: {
                                    padding: {
                                        // bottom: 40
                                    }
                                },
                                valueLabel: {
                                    display: true,
                                    fontSize: 25,
                                    color: '#3e76c1',
                                    backgroundColor: 'rgba(0,0,0,0)',
                                    bottomMarginPercentage: -6
                                },
                            }
                        });

                    })();
                </script>
                <div class="title"><?php echo esc_html($retries_chart_title); ?></div>
                <div class="desc"><?php echo esc_attr($retries_chart_desc); ?></div>
                <?php if ($retries_chart_show_actions) : ?>
                    <div class="actions">
                        <ol>
                            <li><?php _e('Change your password to something more secure.', 'limit-failed-login'); ?></li>
                            <li><?php _e('Make sure WordPress and all your plugins are updated.', 'limit-failed-login'); ?></li>
                            <li><?php echo sprintf(__('<a href="%s" target="_blank">Update to Premium</a> Limit Failed Logins.', 'limit-failed-login'), 'https://www.limitloginattempts.com/info.php?from=plugin-dashboard-status'); ?></li>
                        </ol>
                    </div>
                <?php endif; ?>
            </div>
        </div>
        <div class="info-box-2">
            <div class="section-content">
                <?php
                $chart2_label = '';
                $chart2_labels = array();
                $chart2_datasets = array();

                if ($active_app === 'custom') {

                    $stats_dates = array();
                    $stats_values = array();
                    $date_format = trim(esc_attr(get_option('date_format')), ' yY,._:;-/\\');
                    $date_format = str_replace('F', 'M', $date_format);

                    $dataset = array(
                        'label' => __('Failed Login Attempts', 'limit-failed-login'),
                        'data' => [],
                        'backgroundColor' => 'rgb(54, 162, 235)',
                        'borderColor' => 'rgb(54, 162, 235)',
                        'fill' => false,
                    );

                    if ($api_stats && !empty($api_stats['attempts'])) {

                        foreach ($api_stats['attempts']['at'] as $timest) {

                            $stats_dates[] = date($date_format, $timest);
                        }

                        $chart2_label = __('Requests', 'limit-failed-login');
                        $chart2_labels = $stats_dates;

                        $dataset['data'] = $api_stats['attempts']['count'];
                    }

                    $chart2_datasets[] = $dataset;
                } else {

                    $date_format = trim(get_option('date_format'), ' yY,._:;-/\\');
                    $date_format = str_replace('F', 'M', $date_format);

                    $retries_stats = $this->get_option('retries_stats');

                    if (is_array($retries_stats) && $retries_stats) {

                        $daterange = new DatePeriod(
                                new DateTime(key($retries_stats)),
                                new DateInterval('P1D'),
                                new DateTime()
                        );

                        $chart2_data = array();
                        foreach ($daterange as $date) {

                            $chart2_labels[] = $date->format($date_format);
                            $chart2_data[] = (!empty($retries_stats[$date->format("Y-m-d")])) ? $retries_stats[$date->format("Y-m-d")] : 0;
                        }
                    } else {

                        $chart2_labels[] = (new DateTime())->format($date_format);
                        $chart2_data[] = 0;
                    }


                    $chart2_datasets[] = array(
                        'label' => __('Failed Login Attempts', 'limit-failed-login'),
                        'data' => $chart2_data,
                        'backgroundColor' => 'rgb(54, 162, 235)',
                        'borderColor' => 'rgb(54, 162, 235)',
                        'fill' => false,
                    );
                }
                ?>
                <div class="LFLr-chart-wrap">
                    <canvas id="LFLr-api-requests-chart" style=""></canvas>
                </div>
                <script type="text/javascript">
                    (function() {
                        var ctx = document.getElementById('LFLr-api-requests-chart').getContext('2d');
                        var LFLr_stat_chart = new Chart(ctx, {
                            type: 'line',
                            data: {
                                labels: <?php echo json_encode($chart2_labels); ?>,
                                datasets: <?php echo json_encode($chart2_datasets); ?>
                            },
                            options: {
                                responsive: true,
                                maintainAspectRatio: false,
                                tooltips: {
                                    mode: 'index',
                                    intersect: false,
                                },
                                hover: {
                                    mode: 'nearest',
                                    intersect: true
                                },
                                scales: {
                                    x: {
                                            display: true,
                                            scaleLabel: {
                                                display: false
                                            }
                                    },
                                    y: {
                                            display: true,
                                            scaleLabel: {
                                                display: false
                                            },
                                            ticks: {
                                                beginAtZero: true,
                                            userCallback: function(label, index, labels) {
                                                    if (Math.floor(label) === label) {
                                                        return label;
                                                    }
                                                },
                                            }
                                }
                            }
                            }
                        });

                    })();
                </script>
            </div>
        </div>
    </div>
    <div class="dashboard-section-3">
        <div class="info-box-1">
            <div class="info-box-icon">
                <span class="dashicons dashicons-admin-tools"></span>
            </div>
            <div class="info-box-content">
                <div class="title"><a href="<?php echo esc_url($this->lfl_get_options_page_uri('logs-' . $active_app)); ?>"><?php _e('Tools', 'limit-failed-login'); ?></a></div>
                <div class="desc"><?php _e('View lockouts logs, block or whitelist usernames or IPs, and more.', 'limit-failed-login'); ?></div>
            </div>
        </div>
        <div class="info-box-1">
            <div class="info-box-icon">
                <span class="dashicons dashicons-admin-generic"></span>
            </div>
            <div class="info-box-content">
                <div class="title"><a href="<?php echo esc_url($this->lfl_get_options_page_uri('settings')); ?>"><?php _e('Global Options', 'limit-failed-login'); ?></a></div>
                <div class="desc"><?php _e('Many options such as notifications, alerts, premium status, and more.', 'limit-failed-login'); ?></div>
            </div>
        </div>
    </div>
</div>
