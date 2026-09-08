<?php
use think\facade\Route;

Route::get('/', 'index/index');
Route::get('api/status', 'index/status');
Route::get('api/content/preview', 'index/preview');
Route::get('api/preview', 'index/preview');
Route::get('think', function () {
    return 'hello,ThinkPHP8!';
});
