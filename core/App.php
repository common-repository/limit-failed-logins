<?php

class LFLR_App {

    /**
     * @var null|string
     */
    private $id = null;

    /**
     * @var mixed|string
     */
    private $endpoint = '';

    /**
     * @var array
     */
    private $config = array();

    /**
     * @var array
     */
    private $login_errors = array();

    /**
     * @var null
     */
    public $last_response_code = null;

    /**
     * LFLR_App constructor.
     * @param array $config
     */
    public function __construct(array $config) {

        if (empty($config)) {
            return false;
        }

        $this->id = 'app_' . esc_attr($config['id']);
        $this->api = esc_attr($config['api']);
        $this->config = $config;
    }

    /**
     * @param $error
     * @return bool
     */
    public function lfl_add_error($error) {

        if (!$error)
            return false;

        $this->login_errors[] = $error;
    }

    /**
     * @return array
     */
    public function lfl_get_errors() {

        return $this->login_errors;
    }

    /**
     * @return null|string
     */
    public function lfl_get_id() {
        return $this->id;
    }

    /**
     * @return array
     */
    public function lfl_get_config() {
        return $this->config;
    }

    /**
     * @param $link
     * @return false[]
     */
    public static function lfl_setup($link) {

        $return = array(
            'success' => false,
        );

        if (empty($link)) {

            return $return;
        }

        $link = 'https://' . $link;

        $domain = parse_url(home_url('/'));
        $link = add_query_arg('domain', $domain['host'], esc_url($link));

        $plugin_data = get_plugin_data(LFL_PLUGIN_DIR . '/limit-failed-logins.php');
        $link = add_query_arg('version', esc_attr($plugin_data['Version']), esc_url($link));

        $setup_response = wp_remote_get($link);
        $setup_response_body = json_decode(wp_remote_retrieve_body($setup_response), true);

        if (is_wp_error($setup_response)) {

            $return['error'] = $setup_response->get_error_message();
        } else if (wp_remote_retrieve_response_code($setup_response) === 200) {

            $return['success'] = true;
            $return['app_config'] = $setup_response_body;
        } else {

            $return['error'] = (!empty($setup_response_body['message']) ) ? $setup_response_body['message'] : __('The endpoint is not responding. Please contact your app provider to settle that.', 'limit-failed-login');
            $return['response_code'] = wp_remote_retrieve_response_code($setup_response);
        }

        return $return;
    }

    /**
     * @return bool|mixed
     * @throws Exception
     */
    public function stats() {
        return $this->lfl_request('stats', 'get');
    }

    /**
     * @return bool|mixed
     */
    public static function lfl_stats_global() {
        $response = wp_remote_get('https://api.limitloginattempts.com/v1/global-stats');

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            return false;
        } else {
            return json_decode(sanitize_textarea_field(stripslashes(wp_remote_retrieve_body($response))), true);
        }
    }

    /**
     * @param $data
     * @return bool|mixed
     */
    public function lfl_acl_check($data) 
	{
        $this->lfl_prepare_settings('acl', $data);
        return $this->lfl_request('acl', 'post', $data);
    }

    /**
     * @param $data
     * @return bool|mixed
     */
    public function lfl_acl($data) {
        return $this->lfl_request('acl', 'get', $data);
    }

    /**
     * @param $data
     * @return bool|mixed
     */
    public function acl_create($data) {
        return $this->lfl_request('acl/create', 'post', $data);
    }

    /**
     * @param $data
     * @return bool|mixed
     */
    public function acl_delete($data) {
        return $this->lfl_request('acl/delete', 'post', $data);
    }

    /**
     * @return bool|mixed
     * @throws Exception
     */
    public function lfl_country() {
        return $this->lfl_request('country', 'get');
    }

    /**
     * @param $data
     * @return bool|mixed
     * @throws Exception
     */
    public function lfl_country_add($data) {
        return $this->lfl_request('country/add', 'post', $data);
    }

    /**
     * @param $data
     * @return bool|mixed
     * @throws Exception
     */
    public function lfl_country_remove($data) {
        return $this->lfl_request('country/remove', 'post', $data);
    }

    /**
     * @param $data
     * @return bool|mixed
     */
    public function lfl_country_rule($data) {
        return $this->lfl_request('country/rule', 'post', $data);
    }

    /**
     * @param $data
     * @return bool|mixed
     */
    public function lfl_lockout_check($data) {
        $this->lfl_prepare_settings('lockout', $data);
        return $this->lfl_request('lockout', 'post', $data);
    }

    /**
     * @param int $limit
     * @param string $offset
     * @return bool|mixed
     */
    public function lfl_log($limit = 25, $offset = '') {
        $data = array();

        $data['limit'] = esc_attr($limit);
        $data['offset'] = esc_attr($offset);
        $data['is_short'] = 1;

        return $this->lfl_request('log', 'get', $data);
    }

    public function lfl_get_lockouts($limit = 25, $offset = '') {
        $data = array();

        $data['limit'] = esc_attr($limit);
        $data['offset'] = esc_attr($offset);

        return $this->lfl_request('lockout', 'get', $data);
    }

    /**
     * Prepare settings for API request
     *
     * @param $method
     */
    public function lfl_prepare_settings($method, &$data) {
        $settings = array();

        if (!empty($this->config['settings'])) {
            foreach ($this->config['settings'] as $setting_name => $setting_data) {
                if (in_array($method, esc_attr($setting_data['methods']))) {
                    $settings[$setting_name] = esc_attr($setting_data['value']);
                }
            }
        }

        if ($settings)
            $data['settings'] = $settings;
    }

    /**
     * @param $method
     * @param string $type
     * @param null $data
     * @return bool|mixed
     * @throws Exception
     */
    public function lfl_request($method, $type = 'get', $data = null) {

        if (!$method) {
            throw new Exception('You must to specify API method.');
        }

        $headers = array();
        $headers[$this->config['header']] = esc_attr($this->config['key']);

        if ($type === 'post') {
            $headers['Content-Type'] = 'application/json; charset=utf-8';
        }

        $func = ( $type === 'post' ) ? 'wp_remote_post' : 'wp_remote_get';

        $response = $func($this->api . '/' . $method, array(
            'headers' => $headers,
            'body' => ( $type === 'post' ) ? json_encode($data, JSON_FORCE_OBJECT) : $data
        ));

        $this->last_response_code = wp_remote_retrieve_response_code($response);

        if (is_wp_error($response) || $this->last_response_code !== 200) {
            return false;
        } else {
            return json_decode(sanitize_textarea_field(stripslashes(wp_remote_retrieve_body($response))), true);
        }
    }

}
