<?php
namespace  app\controllers;

use app\components\client_db;
use app\components\MhtFileMaker;
use app\models\BdHostTaskManage;
use kartik\mpdf\Pdf;
use Mpdf\Mpdf;
use yii\data\ActiveDataProvider;
use yii\db\Query;
use yii\grid\GridView;
use yii\helpers\ArrayHelper;

class BbglsController extends BaseController {
    public function actionIndex(){
        $db=new client_db();
        $data = array();
        $post = isset( $_REQUEST['post']) ? intval($_REQUEST['post']) : 0;
        if($post == 1) {
            $data = array('success' => false, 'message' => '操作失败', 'down' => '');
            //$tasks  = intval($_REQUEST['tasks']);//这里$_REQUEST['tasks']是个数组
            $template_conf = array(
                //'name': '模板名',
                'overview' => '综述',
                'risk' => '总体风险分析',
                'risk_lever' => '风险等级分布',
                'risk_type' => '风险类型分布',
                'risk_host' => '所有主机（IP）风险分布',
                'vul_host' => '主机漏洞列表',
                'vul_host_system' => '系统漏洞',
                'vul_host_server' => '服务漏洞',
                'vul_host_application' => '应用漏洞',
                'vul_host_device' => '网络设备漏洞',
                'vul_host_database' => '数据库漏洞',
                'vul_host_virtual' => '虚拟化平台漏洞',
                'risk_web' => 'WEB漏洞列表',
                'vul_web_syscmd' => '系统命令执行',
                'vul_web_sql' => 'SQL注入',
                'vul_web_code' => '代码远程执行',
                'vul_web_file' => '远程文件包含',
                'vul_web_http' => 'HTTP参数污染',
                'vul_web_ldap' => 'LDAP注入',
                'vul_web_script' => '跨站脚本攻击',
                'vul_web_content' => '内容欺骗',
                'vul_web_upload' => '文件上传',
                'vul_web_deny' => '拒绝服务',
                'vul_web_info' => '信息泄露',
                'vul_web_dir' => '目录遍历',
                'vul_web_log' => '日志文件扫描',
                'vul_web_server' => '软件服务检测',
                'vul_web_read' => '任意文件读取',
                'vul_web_database' => '数据库发现',
                'vul_web_backdoor' => '后门发现',
                'vul_web_auth' => '验证绕过',
                'vul_web_config' => '配置不当',
                'vul_web_other' => '其它',
                'risk_pwd' => '弱密码漏洞列表'
            );
            $t_host_list = array(
                'vul_host' => 'vul_host',
                'vul_host_system' => 'vul_host_system',
                'vul_host_server' => 'vul_host_server',
                'vul_host_application' => 'vul_host_application',
                'vul_host_device' => 'vul_host_device',
                'vul_host_database' => 'vul_host_database',
                'vul_host_virtual' => 'vul_host_virtual'
            );

            $t_web_list = array(
                'risk_web' => 'risk_web',
                'vul_web_syscmd' => 'vul_web_syscmd',
                'vul_web_sql' => 'vul_web_sql',
                'vul_web_code' => 'vul_web_code',
                'vul_web_file' => 'vul_web_file',
                'vul_web_http' => 'vul_web_http',
                'vul_web_ldap' => 'vul_web_ldap',
                'vul_web_script' => 'vul_web_script',
                'vul_web_content' => 'vul_web_content',
                'vul_web_upload' => 'vul_web_upload',
                'vul_web_deny' => 'vul_web_deny',
                'vul_web_info' => 'vul_web_info',
                'vul_web_dir' => 'vul_web_dir',
                'vul_web_log' => 'vul_web_log',
                'vul_web_server' => 'vul_web_server',
                'vul_web_read' => 'vul_web_read',
                'vul_web_database' => 'vul_web_database',
                'vul_web_backdoor' => 'vul_web_backdoor',
                'vul_web_auth' => 'vul_web_auth',
                'vul_web_config' => 'vul_web_config',
                'vul_web_other' => 'vul_web_other'
            );

            $rt = filterStr($_REQUEST['rt']);
            $bbtitle = filterStr($_REQUEST['bbtitle']);
            $bbname = filterStr($_REQUEST['bbname']);
            $desc = filterStr($_REQUEST['desc']);
            $epilog = filterStr($_REQUEST['epilog']);
            $kidbb = intval($_REQUEST['kidbb']);
            $template_report = intval($_REQUEST['template_report']);
            //组装需要隐藏的栏目数组
            $templateConfArr = array();
            $temRes = $db->fetch_first("SELECT * FROM template_report WHERE id=$template_report");
            foreach ($temRes as $k => $v) {
                if ($k != 'id' && $k != 'name' && $v == 1) {
                    if (in_array($k, $t_host_list)) {
                        $if_host_list = true;
                    }
                    if (in_array($k, $t_web_list)) {
                        $if_web_list = true;
                    }
                    $templateConfArr[] = $template_conf["$k"];
                }
            }
            if (empty($_REQUEST['tasks'])) {
                $data['message'] = '请选择任务.';
                echo json_encode($data);
                exit;
            }

            if ($bbname == '') {
                $data['message'] = '请填写报表名称.';
                echo json_encode($data);
                exit;
            }
            $theTime = '-' . date('Y-m-d_H:i:s', time());

            if ($_POST['tasks']) {
                $taskss = $_POST['tasks'];
            } elseif ($_GET['tasks']) {
                $taskss = explode(',', $_REQUEST['tasks']);
            }
            //var_dump($taskss);die;
            foreach ($taskss as $key => $val) {
                $tasks = intval($val);
                $tablevul = 'bd_host_result_' . $tasks;
                $tablepwd = 'bd_weakpwd_result_' . $tasks;
                $tablescan = 'bd_web_result_' . $tasks;
                ignore_user_abort(TRUE);
                @set_time_limit(300);
                $date = date("Ymd");
                $day = date('d');
                $dym = "/bdwebserver/nginx/html/web/report";
                $dir = "/bdwebserver/nginx/html/web/report/now";//报表存放文件夹

                if (!file_exists($dir)) mkdir($dir, 0777);

                $file_name = array();
                $maxid = $db->result_first("SELECT MAX(id) FROM " . getTable('reportsmanage') . " WHERE 1");
                $maxid = (!$maxid || $maxid < 1) ? 1 : $maxid + 1;

                exec("cd /bdwebserver/nginx/html/web/report/now; ln -s ../common.js common.js; ln -s ../common.css common.css; ln -s ../bluechar.js; ln -s ../jquery-1.9.1.min.js jquery-1.9.1.min.js");

                $content = $wordcon = $imageCon = '';
                global $act, $show;

                $content = file_get_contents($dym . '/attack_host.html');
                $imgcontent = file_get_contents($dym . '/attack-image.html');  //图片
                $docCon = file_get_contents($dym . '/attack-doc.html');  //doc

                if ($_REQUEST['type'] == 'weakpwd') {
                    if (!in_array($tablepwd, $this->getAllTables())) {
                        $db->execute("CREATE TABLE $tablepwd (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `task_id` varchar(256) DEFAULT NULL COMMENT 'task id',
  `task_name` varchar(256) DEFAULT NULL COMMENT '任务名称',
  `ip` varchar(32) DEFAULT NULL COMMENT '目标ip',
  `vul_name` varchar(255) DEFAULT NULL COMMENT '字典名称',
  `username` varchar(256) DEFAULT NULL COMMENT '用户名',
  `password` varchar(256) DEFAULT NULL COMMENT '密码',
  `port` varchar(256) DEFAULT NULL COMMENT '服务端口号',
  `proto` varchar(256) DEFAULT NULL COMMENT '协议：TCP/UDP',
  `report` int(11) DEFAULT '0' COMMENT '报表id',
  `vul_id` int(11) DEFAULT '0' COMMENT '弱口令参数对应vul_id,在weak_vul_list表中',
  `level` varchar(10) DEFAULT 'H' COMMENT '危险等级',
  `description` text COMMENT '描述',
  `solution` text COMMENT '解决方案',
  `dbname` varchar(256) DEFAULT NULL COMMENT '结果属于的库名',
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=19 DEFAULT CHARSET=utf8;
");
                    }
                    // $content = file_get_contents($dym . '/attack_host.html');

                    $total = \Yii::$app->db->createCommand("select count(1) as num from $tablepwd")->queryColumn()[0];
                    $rows = \Yii::$app->db->createCommand("select * from $tablepwd")->queryAll();
                    $main_tasks = \Yii::$app->db->createCommand("SELECT * FROM bd_weakpwd_task_manage WHERE id='$tasks'")->queryOne();
                    $targets = $rows['target'];
                    // var_dump($num);die;
                    $content = str_replace('{$weak_num}', $total, $content);
                    $content = str_replace('{$type}', '弱密码', $content);

                    $docCon = str_replace('{$weak_num}', $total, $docCon);
                    $docCon = str_replace('{$type}', '弱密码', $docCon);

                    $level = $this->getLevel($rows);
                    $h_sum = $m_sum = $l_sum = 0;
                    foreach ($rows as $v) {
                        if ($v['level'] == 'H') {

                            $h_sum++;
                        }
                        if ($v['level'] == 'M') {

                            $m_sum++;
                        }
                        if ($v['level'] == 'L') {

                            $l_sum++;
                        }
                    }
                    //var_dump($h_sum,$m_sum);die;
                    $content = str_replace('{$level}', $level, $content);
                    $content = str_replace('{$h_sum}', $h_sum, $content);
                    $content = str_replace('{$m_sum}', $m_sum, $content);
                    $content = str_replace('{$l_sum}', $l_sum, $content);

                    $docCon = str_replace('{$level}', $level, $docCon);
                    $docCon = str_replace('{$h_sum}', $h_sum, $docCon);
                    $docCon = str_replace('{$m_sum}', $m_sum, $docCon);
                    $docCon = str_replace('{$l_sum}', $l_sum, $docCon);

                    //风险分布图
                    $h_fx = number_format((($h_sum / $total) * 100), 2, '.', '');
                    $m_fx = number_format((($m_sum / $total) * 100), 2, '.', '');
                    $l_fx = number_format((($l_sum / $total) * 100), 2, '.', '');
                    $data1 = '{name:"高风险(' . $h_sum . ')个",value:[' . $h_fx . '],color:"#ffa500"},{name:"中风险(' . $m_sum . ')个",value:[' . $m_fx . '],color:"#f737ec"},{name:"低风险(' . $l_sum . ')个",value:[' . $l_fx . '],color:"#6060fe"}';
                    $content = str_replace('{$data_level}', $data1, $content);
                    $imgcontent = str_replace('{$data_level}', $data1, $imgcontent);

                    /*漏洞类型分布图*/
                    $category = $db->fetch_all("select id,vul_name from bd_weakpwd_vul_lib ");
                    $category = ArrayHelper::map($category, 'id', 'vul_name');
                    $str = $type_list = '';
                    foreach ($category as $c_i => $v) {
                        $str .= '<li><a class="sub" href="#t3_' . $c_i . '" >3.' . $c_i . '、' . $v . '</a></li>';
                        $type_list .= '<div  class="y-report-ui-comp-section weakSS">
                                        <div class="y-report-ui-element-title-level-2" id="t3_' . $c_i . '">3.' . $c_i . '、' . $v . '</div>
                                        <div >' . $this->gridview($tablepwd, $c_i) . '</div>
                                    </div>';
                    }
                    $content = str_replace('{$type_li}', $str, $content);
                    $content = str_replace('{$type_list}', $type_list, $content);

                    $docCon = str_replace('{$type_li}', $str, $docCon);
                    $docCon = str_replace('{$type_list}', $type_list, $docCon);
                    //var_dump($category);die;
                    $vuls_type = $db->fetch_all("SELECT COUNT(1) as num,t.id as category from(
select a.vul_name,a.vul_id,b.id from $tablepwd a LEFT JOIN bd_weakpwd_vul_lib b on a.vul_id = b.vul_id
) as t  GROUP BY vul_id
");
                    foreach ($category as $i => $v) {
                        $arr[$i]['name'] = $v;
                        $arr[$i]['value'] = number_format(0 / $total * 100, 2);
                        $arr[$i]['color'] = $this->randrgb();
                    }
                    // var_dump($arr);die;
                    $total = array_sum(ArrayHelper::getColumn($vuls_type, 'num'));
                    //var_dump(array_diff(ArrayHelper::getColumn($vuls_type,'category'),$category));die;
                    foreach ($vuls_type as $i => $v) {
                        $arr[$v['category']]['name'] = $category[$v['category']];
                        $arr[$v['category']]['value'] = number_format($v['num'] / $total * 100, 2);
                        // $arr[$v['category']]['color'] = $this->randrgb();
                    }
                    sort($arr);
                    // echo json_encode($arr);die;
                    //var_dump($arr);die;
                    $content = str_replace('{$data_type}', json_encode($arr), $content);
                    $imgcontent = str_replace('{$data_type}', json_encode($arr), $imgcontent);
                    /*TOP10危险IP所有漏洞统计图*/
                    //$ipld = $db->fetch_all("SELECT ip FROM $tablevul GROUP BY ip DESC LIMIT 10");
                    $topid = [];
                    $ipld = $db->fetch_all("
        select ip from
            (select ip ,sum(case when level='H' then 1 else 0 end ) as hnum ,
            sum(case when level='M' then 1 else 0 end ) as mnum ,
            sum(case when level='L' then 1 else 0 end ) as lnum ,
            sum(case when level='L' then 1 else 0 end ) as inum
            from $tablepwd
            group by ip) as iptem
            ORDER BY hnum DESC, mnum desc,lnum DESC limit 10
    ");
                    //var_dump($ipld);die;
                    foreach ($ipld as $k => $v) {
                        array_push($topid, "'" . $v['ip'] . "'");
                    }
                    foreach ($ipld as $k => $v) {//根据IP读取统计紧急
                        $tum = $db->result_first("SELECT COUNT(1) AS tum FROM $tablepwd WHERE level ='C' AND ip = '" . $v['ip'] . "'");
                        $tum = $tum > 0 ? $tum : 0;
                        $ldcnum[] = $tum;
                    }
                    foreach ($ipld as $k => $v) {//根据IP读取统计高风险
                        $tum = $db->result_first("SELECT COUNT(1) AS tum FROM $tablepwd WHERE level ='H' AND ip = '" . $v['ip'] . "'");
                        $tum = $tum > 0 ? $tum : 0;
                        $ldhnum[] = $tum;
                    }
                    foreach ($ipld as $k => $v) {//根据IP读取统计中风险
                        $tum = $db->result_first("SELECT COUNT(1) AS tum FROM $tablepwd WHERE level ='M' AND ip = '" . $v['ip'] . "'");
                        $tum = $tum > 0 ? $tum : 0;
                        $ldmnum[] = $tum;
                    }
                    foreach ($ipld as $k => $v) {//根据IP读取统计低风险
                        $tum = $db->result_first("SELECT COUNT(1) AS tum FROM $tablepwd WHERE level ='L' AND ip = '" . $v['ip'] . "'");
                        $tum = $tum > 0 ? $tum : 0;
                        $tum_i = $db->result_first("SELECT COUNT(1) AS tum FROM $tablepwd WHERE level ='I' AND ip = '" . $v['ip'] . "'");
                        $tum_i = $tum_i > 0 ? $tum_i : 0;
                        $ldlnum[] = $tum + $tum_i;
                    }
                    foreach ($ipld as $k => $v) {//根据IP读取安全信息
                        $tum = $db->result_first("SELECT COUNT(1) AS tum FROM $tablepwd WHERE level ='I' AND ip = '" . $v['ip'] . "'");
                        $tum = $tum > 0 ? $tum : 0;
                        $ldinum[] = $tum;
                    }
                    $data7 = '{name:"高风险",value:[' . join(',', $ldhnum) . '],color:"#ffa500"},{name:"中风险",value:[' . join(',', $ldmnum) . '],color:"#f737ec"},{name:"低风险",value:[' . join(',', $ldlnum) . '],color:"#6060fe"}';
                    $content = str_replace('{$dataip}', join(',', $topid), $content);
                    $content = str_replace('{$data7}', $data7, $content);
                    $imgcontent = str_replace('{$dataip}', join(',', $topid), $imgcontent);
                    $imgcontent = str_replace('{$data7}', $data7, $imgcontent);

                    /*3.按漏洞类型列表*/
                    $str = '';
                    foreach ($category as $c_i => $v) {
                        $str .= '<li><a class="sub" href="#t3_' . $c_i . '" >3.' . $c_i . '、' . $v . '</a></li>';
                    }
                    $content = str_replace('{$type_li}', $str, $content);
                    $content = str_replace('{$vuls_sys_list}', $this->gridview($tablepwd, 'type', $rt), $content);

                    $docCon = str_replace('{$type_li}', $str, $docCon);
                    $docCon = str_replace('{$vuls_sys_list}', $this->gridview($tablepwd, 'type', $rt), $docCon);

                    /* 4.安全等级详细信息*/
                    $content = str_replace('{$vuls_level_list}', $this->gridview($tablepwd, 'level', $rt), $content);
                    $docCon = str_replace('{$vuls_level_list}', $this->gridview($tablepwd, 'level', $rt), $docCon);

                    /* 5.ip详细信息*/
                    $content = str_replace('{$vuls_ip_list}', $this->gridview($tablepwd, 'ip', $rt), $content);
                    $docCon = str_replace('{$vuls_ip_list}', $this->gridview($tablepwd, 'ip', $rt), $docCon);

                    $sql = "select * from bd_weakpwd_task_manage WHERE id=$val";
                    $row = $db->fetch_row($sql);
                    // var_dump($row);die;
                    $content = str_replace('{$target}', $row['target'], $content);
                    $docCon = str_replace('{$target}', $row['target'], $docCon);
                    if ($row['start_time'] == 0) {
                        $start = '未开始';
                    } else {
                        $start = date('Y-m-d H:i:s', $row['start_time']);
                    }
                    if ($row['end_time'] == 0) {
                        $end = '未结束';
                    } else {
                        $end = date('Y-m-d H:i:s', $row['end_time']);
                    }
                    $content = str_replace('{$starttime}', $start, $content);
                    $content = str_replace('{$endtime}', $end, $content);

                    $docCon = str_replace('{$starttime}', $start, $docCon);
                    $docCon = str_replace('{$endtime}', $end, $docCon);
                }
            }
        }

        if($rt=='html') {
            $content = str_replace('{$cover}','',$content);
            $content = str_replace('{$cover2}','',$content);
            $content = str_replace('{$cover_time}','',$content);

            file_put_contents($dir . '/attack-'.$tasks. ".html", $content, LOCK_EX);
        }elseif($rt=='pdf'){

            $content = str_replace('{$cover}','<img src="'.\Yii::$app->request->getHostInfo().'/report/cover.png" style="">',$content);
            $content = str_replace('{$cover2}','<img src="'.\Yii::$app->request->getHostInfo().'/report/cover2.png" style="">',$content);
            $content = str_replace('{$cover_time}','<p style="text-align: center;margin: 50px 0 100px 30px"><font style="font-size: 20px">'.date('Y-m-d H:i:s',time()).'</font></p>',$content);

            $preg ='/<style>.*?<\/style>/si';
            $content = preg_replace($preg,'',$content);
            $preg ='/<div id="sidebar" class="opened">.*?<\/div>/si';
            //preg_match($preg,$content,$match);
            $content =preg_replace($preg,'',$content);
            $html='attack-'.$tasks.'.html';
            file_put_contents($dir . '/'.$html, $content, LOCK_EX);
            //html转换成pdf
            $pdf='attack-'.$tasks.'.pdf';
            $exec="cd /bdwebserver/nginx/html/web/report/now; /bdwebserver/nginx/wkhtmltox/bin/wkhtmltopdf ./$html ./$pdf";
            system($exec);

        }else{ //doc
            $type=$_REQUEST['type'];
            file_put_contents($dir . "/attack-img-$type-$tasks.php", $imgcontent, LOCK_EX);
            $exec="ln -s $dir/attack-img-$type-$tasks.php /bdwebserver/nginx/html/views/bbgl/attack-img-$type-$tasks.php";
            //echo $exec;die;
            exec($exec);

            //生成图片
            $exec = "cd /nginx/html/report/now; /nginx/wkhtmltox/bin/wkhtmltoimage --crop-x 50 --crop-y 5 --crop-w 800 --crop-h 300 ".\Yii::$app->request->getHostInfo()."/bbgl/htmltoimg?img=attack-img-$type-$tasks.php  $dir/{$tasks}-{$date}-1.jpg";
            exec($exec);
            $exec = "cd /nginx/html/report/now; /nginx/wkhtmltox/bin/wkhtmltoimage --crop-x 50 --crop-y 300 --crop-w 800 --crop-h 300 ".\Yii::$app->request->getHostInfo()."/bbgl/htmltoimg?img=attack-img-$type-$tasks.php  $dir/{$tasks}-{$date}-2.jpg";
            exec($exec);
            $exec = "cd /nginx/html/report/now; /nginx/wkhtmltox/bin/wkhtmltoimage --crop-x 50 --crop-y 600 --crop-w 800 --crop-h 300 ".\Yii::$app->request->getHostInfo()."/bbgl/htmltoimg?img=attack-img-$type-$tasks.php  $dir/{$tasks}-{$date}-3.jpg";
            exec($exec);
            $docCon = str_replace('{image1}',\Yii::$app->request->hostInfo."/report/now/$bbname-$type-doc-$date/{$tasks}-{$date}-1.jpg",$docCon);
            $docCon = str_replace('{image2}',\Yii::$app->request->hostInfo."/report/now/$bbname-$type-doc-$date/{$tasks}-{$date}-2.jpg",$docCon);
            $docCon = str_replace('{image3}',\Yii::$app->request->hostInfo."/report/now/$bbname-$type-doc-$date/{$tasks}-{$date}-3.jpg",$docCon);
            $docCon = str_replace('{image_sg}',\Yii::$app->request->hostInfo."/report/now/$bbname-$type-doc-$date/7.png",$docCon);
            //var_dump($docCon);die;
            file_put_contents($dir . "/attack-doc-{$tasks}.doc", $docCon, LOCK_EX);

        }
    }
}