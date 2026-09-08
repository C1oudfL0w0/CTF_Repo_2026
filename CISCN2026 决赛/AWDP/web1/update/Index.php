<?php

namespace app\controller;

use app\BaseController;
use think\facade\Lang;
use think\response\Json;

class Index extends BaseController
{
  public function index()
  {
    $lang = Lang::getLangSet();
    $msg = Lang::get('dashboard.title');
    if ($msg === 'dashboard.title') {
      $msg = 'Content Delivery Console';
    }
    $title = htmlentities($msg, ENT_QUOTES, 'UTF-8');
    $langHtml = htmlentities($lang, ENT_QUOTES, 'UTF-8');
    $version = htmlentities(\think\facade\App::version(), ENT_QUOTES, 'UTF-8');

    return <<<HTML
<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{$title}</title>
  <style>
    :root{--bg:#f4f7fb;--card:#fff;--muted:#64748b;--line:#e2e8f0;--blue:#2563eb;--green:#059669;--dark:#0f172a}
    *{box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;background:var(--bg);margin:0;color:var(--dark)}
    .top{height:64px;background:#0f172a;color:white;display:flex;align-items:center;justify-content:space-between;padding:0 34px;box-shadow:0 6px 22px rgba(15,23,42,.18)}
    .brand{font-weight:700;letter-spacing:.2px}.brand small{font-weight:500;color:#94a3b8;margin-left:10px}.locale a{color:#c7d2fe;text-decoration:none;margin-left:14px;font-size:14px}.locale a.active{color:white;font-weight:700}
    .wrap{max-width:1120px;margin:32px auto;padding:0 20px}.hero{background:linear-gradient(135deg,#ffffff,#eef6ff);border:1px solid var(--line);border-radius:22px;padding:30px;box-shadow:0 16px 45px rgba(15,23,42,.07)}
    h1{font-size:30px;margin:0 0 10px}.sub{color:var(--muted);line-height:1.7;margin:0;max-width:760px}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin:22px 0}.card{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:20px;box-shadow:0 8px 26px rgba(15,23,42,.045)}
    .k{color:var(--muted);font-size:13px}.v{font-size:28px;font-weight:800;margin-top:8px}.ok{color:var(--green)}.panel{display:grid;grid-template-columns:2fr 1fr;gap:18px;margin-top:20px}.list{margin:0;padding:0;list-style:none}.list li{display:flex;justify-content:space-between;border-bottom:1px solid var(--line);padding:13px 0;color:#334155}.list li:last-child{border-bottom:0}.badge{display:inline-block;border-radius:999px;background:#dbeafe;color:#1d4ed8;padding:4px 10px;font-size:12px}.muted{color:var(--muted)}code{background:#f1f5f9;border:1px solid #e2e8f0;border-radius:7px;padding:2px 6px}.foot{margin-top:20px;color:#94a3b8;font-size:13px}
    @media(max-width:880px){.grid{grid-template-columns:repeat(2,1fr)}.panel{grid-template-columns:1fr}.top{padding:0 18px}}@media(max-width:520px){.grid{grid-template-columns:1fr}.locale{display:none}}
  </style>
</head>
<body>
  <header class="top">
    <div class="brand">ContentHub <small>ops console</small></div>
    <nav class="locale">
      <a class="active" href="/?locale=zh-cn">中文</a>
      <a href="/?locale=en-us">English</a>
    </nav>
  </header>
  <main class="wrap">
    <section class="hero">
      <span class="badge">production</span>
      <h1>{$title}</h1>
      <p class="sub">用于管理站内公告、活动横幅与多区域内容投放。系统会根据工作区策略自动选择素材版本，并记录必要的访问审计信息用于排障。</p>
    </section>

    <section class="grid">
      <div class="card"><div class="k">今日发布</div><div class="v">18</div></div>
      <div class="card"><div class="k">素材覆盖率</div><div class="v ok">96%</div></div>
      <div class="card"><div class="k">当前工作区</div><div class="v" style="font-size:22px">{$langHtml}</div></div>
      <div class="card"><div class="k">Framework</div><div class="v" style="font-size:22px">TP {$version}</div></div>
    </section>

    <section class="panel">
      <div class="card">
        <div class="k">近期投放计划</div>
        <ul class="list">
          <li><span>summer-campaign-banner</span><span class="muted">灰度中</span></li>
          <li><span>campus-final-notice</span><span class="muted">待复核</span></li>
          <li><span>security-maintenance-window</span><span class="muted">已发布</span></li>
        </ul>
      </div>
      <div class="card">
        <div class="k">接口摘要</div>
        <p><code>/api/status</code></p>
        <p><code>/api/content/preview?key=campaign.banner</code></p>
        <p class="muted">仅返回当前工作区下的素材渲染结果。</p>
      </div>
    </section>
    <div class="foot">© ContentHub Ops · delivery review enabled</div>
  </main>
</body>
</html>
HTML;
  }

  public function status(): Json
  {
    return json([
      'status' => 'ok',
      'service' => 'content-hub',
      'workspace' => Lang::getLangSet(),
      'time' => date(DATE_ATOM),
    ]);
  }

  public function preview(): Json
  {
    $key = (string) request()->param('key', 'campaign.banner');
    if ($key)
      $value = Lang::get("zh-cn");
    if ($value === $key) {
      $value = 'Default campaign material';
    }
    return json([
      'key' => $key,
      'value' => $value,
      'workspace' => "app",
    ]);
  }
}

