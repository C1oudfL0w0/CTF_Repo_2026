<?php

namespace app\middleware;

use Closure;
use think\Request;
use think\Response;

/**
 * 内部访问审计：用于记录内容投放控制台的请求上下文。
 * 生产环境中保留轻量访问轨迹，便于定位运营侧素材渲染与区域切换问题。
 */
class AccessTrace
{
    public function handle(Request $request, Closure $next): Response
    {
        $this->writeAccessLog($request);
        return $next($request);
    }

    private function writeAccessLog(Request $request): void
    {
        $runtime = app()->getRuntimePath();
        $dir = $runtime . 'log';
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }

        $ua = (string) $request->header('user-agent', '-');
        if (strlen($ua) > 600) {
            $ua = substr($ua, 0, 600);
        }

        $ua = str_replace(["\r", "\n"], ' ', $ua);  // 过滤换行符
        $line = sprintf(
            "[%s] ip=%s method=%s path=%s ua=%s\n",
            date('c'),
            $request->ip(),
            $request->method(),
            '/' . ltrim($request->pathinfo(), '/'),
            $ua
        );

        @file_put_contents($dir . DIRECTORY_SEPARATOR . 'access.log', $line, FILE_APPEND | LOCK_EX);
    }
}
