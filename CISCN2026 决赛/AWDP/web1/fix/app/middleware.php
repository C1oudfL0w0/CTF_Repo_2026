<?php
// 全局中间件定义文件
return [
    // 多语言加载
    \think\middleware\LoadLangPack::class,
    // 内部访问审计
    \app\middleware\AccessTrace::class,
];
