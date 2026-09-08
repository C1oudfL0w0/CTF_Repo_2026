<?php
// +----------------------------------------------------------------------
// | ThinkPHP [ WE CAN DO IT JUST THINK ]
// +----------------------------------------------------------------------
// | Copyright (c) 2006-2019 http://thinkphp.cn All rights reserved.
// +----------------------------------------------------------------------
// | Licensed ( http://www.apache.org/licenses/LICENSE-2.0 )
// +----------------------------------------------------------------------
// | Author: liu21st <liu21st@gmail.com>
// +----------------------------------------------------------------------

use think\App;

// [ 应用入口文件 ]

require __DIR__ . '/../vendor/autoload.php';

// 执行HTTP应用并响应
$app = new App();
$http = $app->http;
// PHP 8.4+ 兼容：框架反射兼容层的弃用提示不影响题目逻辑
error_reporting(E_ALL & ~E_DEPRECATED & ~E_USER_DEPRECATED);

$response = $http->run();

$response->send();

$http->end($response);
