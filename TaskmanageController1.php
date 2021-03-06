<?php
namespace app\controllers;
/**
 * 任务管理
 * author: hjf
 * createtime 2017年4月16日17:27:58
 */
use app\components\client_db;
use app\models\BdHostTaskManage;
use app\models\BdWeakpwdTaskManage;
use app\models\BdWebTaskManage;
use app\models\TaskManage;
use Yii;
use yii\filters\AccessControl;
use yii\helpers\ArrayHelper;
use yii\web\Controller;
class TaskmanageController extends BaseController
{
    /**
     * @列表页
     */
    function actionIndex()
    {
        global $db, $act;
        $aData = array();
       // return $this->render('index');
       template2($act . '/index', $aData);
    }


    /**
     * @查看页
     */
    function actionView()
    {
        global $act;
//       var_dump($_GET);die;
        template2($act . '/view', array('type'=>$_GET['type']));
    }

    /**
     * @ 主机漏洞查看页
     */
    function actionVulhostview()
    {
        global $act;
        template2($act . '/vulhostview', array());
    }

    /**
     * @ WEB漏洞查看页
     */
    function actionVulwebview()
    {
        global $act;
        template2($act . '/vulwebview', array());
    }

    /**
     * @获取列表数据
     */
    function actionLists()
    {
        global $db;
        $sPost = $_POST;
        $page = intval($sPost['start']);
        $perpage = intval($sPost['length']);
        $type = intval($sPost['type']);
        $task_name = filterStr($sPost['task_name']);    //任务名称
        $status = filterStr($sPost['status']);    //任务状态
        $rows = array();
        $page = $page > 1 ? $page : 1;
        $offset = ($page-1)*$perpage;

        $total1 = $db->result_first("SELECT COUNT(`id`) as num FROM bd_weakpwd_task_manage ");
        $total2 = $db->result_first("SELECT COUNT(`id`) as num FROM bd_host_task_manage");
        $total3 = $db->result_first("SELECT COUNT(`id`) as num FROM bd_web_task_manage");
        $total=$total1+$total2 +$total3;
        $maxPage = ceil($total / $perpage);
        $page = $page >= $maxPage ? $maxPage : $page;
        $rows=array();
        if ($total) {
            $where='WHERE 1=1 ';
            $start = ($page - 1) * $perpage;
            if (!empty($task_name)) {
                $where .= " AND `name` LIKE '%{$task_name}%'";
            }
            if (!empty($status)) {
                $where .= " and `status` = $status";
            }
            $weak_rows=$db->fetch_all("select * from bd_weakpwd_task_manage $where  ");
            foreach ($weak_rows as $k=>$v){
                $weak_rows[$k]['type']='弱密码';
            }
            $host_rows=$db->fetch_all("select * from bd_host_task_manage $where  ");
            foreach ($host_rows as $k=>$v){
                $host_rows[$k]['type']='主机';
            }
            $web_rows=$db->fetch_all("select * from bd_web_task_manage $where");
            foreach ($web_rows as $k=>$v){
                $web_rows[$k]['type']='web';
            }

            $rows=array_merge($weak_rows,$host_rows,$web_rows);
           // var_dump($rows);die;

        }
        foreach ($rows as $k=>$v){
            $rows[$k]['task_name']=$v['name'];
            $rows[$k]['task_status']=$v['status'];
            $rows[$k]['starttime']=$v['start_time'] !=0 ? date('Y-m-d H:i:s',$v['start_time']) : 0;
            $rows[$k]['endtime']= $v['end_time'] !=0 ? date('Y-m-d H:i:s',$v['end_time']) : 0;
        }
        $rows=array_slice($rows,$offset,$perpage);
  //     var_dump($rows);die;

        //获取风险总数
        //$data['risk_sum'] = $db->fetch_all("SELECT * FROM history_task_sum ORDER BY num desc LIMIT 1");
        $risk_sum = $db->fetch_first("SELECT * FROM history_task_sum ORDER BY num desc");
        $risk_sum_str = $risk_sum['h'] . '/' . $risk_sum['m'] . '/' . $risk_sum['l'] . '/' . $risk_sum['t'];

        //获取任务完成状态
        $data['finish']=1;

        //获取正在检测的任务
        $checking_rows=[];
        foreach($rows as $v){
            if($v['status']==5 || $v['status']==6){
                $checking_rows[]=$v;
            }
            $data['finish']=0;
        }
        $msg='';
        foreach ($checking_rows as $v){
            $msg.='正在检测:'.$v['name'].'('.$v['type'].')'.';IP/域名:'.$v['target']."\r\n";
            $data['time'] = time() - strtotime($v['start_time']);
        }
        $data['check_msg'] = $msg;
        $data['risk_sum_str'] = $risk_sum_str;
        $data['Rows'] = $rows;
        $data['Total'] = $total;
        echo json_encode($data);exit;
    }

    /**
     * @新增web登录扫
     */
    function actionLoginwebscan()
    {
        global $db, $act, $show;
        $sPost = $_POST;
        $str = '';
        $way = $sPost['way'];
        $getpostway = $sPost['getpostway'];
        $waydata = $sPost['waydata'];
        $cookiekeyvalue = $sPost['cookiekeyvalue'];
        $loginUrl = $sPost['loginUrl'];
        $targetDomain = $sPost['target_domain'];

        if (!empty($targetDomain)) {
            $login_domain = substr($loginUrl, 0, strpos($loginUrl, '/', 8));
            if (empty($login_domain))
                $login_domain = $loginUrl;
            //验证 登录域名必须包含在扫描对象的域名中！
            $targrt_domain = nl2br($targetDomain);  //将分行符"\r\n"转义成HTML的换行符"<br />"
            $targrt_domain = str_replace("<br />", ",", $targrt_domain);
            $targrt_domain = str_replace("\r\n", "", $targrt_domain);
            $a_domain = explode(",", $targrt_domain);
            array_filter($a_domain);
            if (!in_array($login_domain, $a_domain)) {
                $data['success'] = false;
                $data['msg'] = '登录域名必须包含在扫描对象的域名中！';
                echo json_encode($data);
                exit;
            }
        }

        if ($way == 1) {
            $str = $getpostway . '|' . $loginUrl . '|' . $waydata;
        } else {
            $str = '3|' . $loginUrl . '|' . $waydata;
        }
        $guid = create_guid();
        $guidfile = $guid . ".txt";
        $addfileshell = '/var/waf/logindata/' . $guidfile;
        file_put_contents($addfileshell, $str);

        $doShell = '/usr/bin/python /var/waf/LoginCheck.py ' . $guid;
        shellResult($doShell);

        if (file_exists('/var/waf/logindata/' . $guid . '.txt')) {
            $logincookie = file_get_contents('/var/waf/logindata/' . $guid . '.txt');
        }
        if (file_exists('/usr/local/nginx/html/report/logindata/' . $guid . '.html')) {
            $success = true;
            $msg = "操作成功";
        } else {
            $success = false;
            $msg = "html文件不存在，操作失败";
        }
        if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] == 'on')
            $http = 'https://';
        else
            $http = 'http://';
        //$data['loginpage'] = 'http://172.16.7.33/index.html';
        $loginpage = $http . $_SERVER['HTTP_HOST'] . '/report/logindata/' . $guid . '.html';
        $data['loginpage'] = $loginpage;
        $data['success'] = $success;
        $data['msg'] = $msg;
        $data['data'] = $logincookie;
        echo json_encode($data);
        exit;
    }

    //处理ip
    function deal_ip($chuli_ip,$sPost){
        $post_ips='';
        if (!empty($chuli_ip)) {
            $arr_ips = explode("\r\n", $chuli_ip);
            if (count($arr_ips) != count(array_unique($arr_ips))) {
                $data['success'] = false;
                $data['msg'] = '请勿输入相同的ip';
                echo json_encode($data);
                exit;
            }
            //验证单个ip是否在段ip中
            $arr = $arr2 = array();
            foreach ($arr_ips as $k => $v) {
                $a_tar = explode("-", trim($v));
                if (count($a_tar) == 2) {
                    $arr[$k][] = ip2long($a_tar[0]);
                    $arr[$k][] = ip2long($a_tar[1]);
                } else {
                    $arr2[] = ip2long($a_tar[0]);
                }
            }
            //var_dump($arr,$arr2);die;
            foreach ($arr as $key => $val) {
                foreach ($arr2 as $v) {
                    if ($v >= $val[0] && $v <= $val[1]) {
                        $data['success'] = false;
                        $data['msg'] = '请检查输入ip,是否已重复';
                        echo json_encode($data);
                        exit;
                    }
                }
            }
            unset($arr, $arr2);
            //验证单个ip是否在段ip中END
            array_filter($arr_ips);
            //启用pptp时，不允许扫描本机ip
            if ($sPost['pptp_enable'] == 1) { // lousaoip&lousaomask==renwuip&lousaomask
                $ipshell = "/sbin/ifconfig eth1 |awk -F'[ :]+' 'NR==2{print $4}'";
                $ipshell2 = "/sbin/ifconfig eth1 |awk -F'[ :]+' 'NR==2{print $8}'";
                $ipfh = popen($ipshell, 'r');
                $lousaoip = fgets($ipfh);
                pclose($ipfh);
                $ipfh2 = popen($ipshell2, 'r');
                $lousaomask = fgets($ipfh2);
                pclose($ipfh2);
                $lousaoip = str_replace("\n", '', $lousaoip);
                $lousaomask = str_replace("\n", '', $lousaomask);

                $lousaoip = ip2long($lousaoip);
                $lousaomask = ip2long($lousaomask);
                $lousao = ($lousaoip & $lousaomask);
                //var_dump($lousaoip&$lousaomask);exit;
                //$myIp = substr($myIp,0,strrpos($myIp,'.'));
                foreach ($arr_ips as $v) {
                    $x = explode('-', $v);
                    //$wangduan = substr($v,0,strrpos($x[0],'.'));
                    $renwu = (ip2long($x[0]) & $lousaomask);
                    if ($lousao == $renwu) {
                        $data['success'] = false;
                        $data['msg'] = '启用pptp时，不允许扫描同一网段';
                        echo json_encode($data);
                        exit;
                    }
                }
            }
           // var_dump($arr_ips);die;
            foreach ($arr_ips as $k => $v) {
                //把2001::1:200:7-20 处理为 2001::1:200:7-2001::1:200:20
                $v = $this->ips_chuli($v);

                $post_ips = $v . "\r\n" . $post_ips;
            }
            //$post_ips=trim($post_ips,',');
            $sPost['target_ip'] = $post_ips;
        }else{
            $sPost['target_ip']='';
        }
        return $sPost['target_ip'];
    }

    //处理域名
    function deal_domain($chuli_domain,$sPost){
        $post_domains = '';
        if (!empty($chuli_domain)) {
            $cl_domain = explode("\r\n", $chuli_domain);
            if (count($cl_domain) != count(array_unique($cl_domain))) {
                $data['success'] = false;
                $data['msg'] = '请勿输入相同的域名';
                echo json_encode($data);
                exit;
            }
            //$cl_domain = array_unique($cl_domain);
            array_filter($cl_domain);
            foreach ($cl_domain as $k => $v) {
                $post_domains = $v . "\r\n" . $post_domains;
            }
        }
        $sPost['target_domain'] = $post_domains;
        return $sPost['target_domain'];
    }

    //添加任务
    function addTask($sRows,$icount,$i_count,$target,$task_name,$userid,$sPost){
        global $db,$act,$show;
       // $iTotal = $db->result_first("SELECT COUNT(`task_name`) FROM task_manage where task_name='" . $sRows['task_name'] . "'");
        if($sPost['weak_enable']==1){
            $type=3;
            $iTotal = $db->result_first("SELECT COUNT(`name`) FROM bd_weakpwd_task_manage where name='" . $sRows['task_name'] . "'");
        }elseif($sPost['web_enable']==1){
            $type=2;
            $iTotal = $db->result_first("SELECT COUNT(`task_name`) FROM bd_web_task where task_name='" . $sRows['task_name'] . "'");
        }else{
            $type=1;

        }
        if (!empty($iTotal)) {
            $data['success'] = false;
            $data['msg'] = $sRows['task_name'] . '已存在，请更换';
            echo json_encode($data);exit;
        }

        $sRows['ipnum'] = $icount;
        $ipnum = $db->result_first("SELECT ipnum FROM bd_sys_sysinfo ");
        $ipnum = intval($ipnum);

//        if ($ipnum != 0 && $ipnum != -1) {
//            $totalipnum = $db->result_first("SELECT SUM(`ipnum`) FROM bd_weakpwd_task_manage");
//            $avaliatenum = $ipnum - intval($totalipnum);//var_dump($i_count , $avaliatenum);die;
//            if ($i_count > $avaliatenum) {
//                $data['success'] = false;
//                //$data['msg'] = '可扫描IP数量不能超过'.$ipnum.'（' . $avaliatenum . '）';
//                $data['msg'] = '可扫描IP数量不能超过'.$ipnum.'（' . $totalipnum . '）';
//                echo json_encode($data);exit;
//            }
//        }

        $sRows['port_state'] = 0;
        $sRows['web_getdomain_state'] = 0;
        $sRows['web_getdomain_policy'] = 0;
        $sRows['user_id'] = $userid;
        $sRows['task_status'] = 2;
        $sRows['web_status'] = 2;
        $sRows['weak_status'] = 2;
        $sRows['host_progress'] = -1;
        $sRows['host_status'] = 2;
        $sRows['i'] = 0;
        $sRows['l'] = 0;
        $sRows['m'] = 0;
        $sRows['h'] = 0;
        $sRows['c'] = 0;
        $sRows['task_uuid'] = uuid();
        $sField = "";
        $sValue = "";
        $nField = "";
        $nValue = "";
        foreach ($sRows as $k => $v) {
            $sField .= $k . ",";
            $sValue .= "'" . $v . "',";
            switch ($k) {
                case 'task_name':
                    $nField .= $k . ",";
                    $nValue .= "'" . $v . "',";
                    break;
                case 'target':
                    $nField .= $k . ",";
                    $ntmp = explode('##', $v);
                    $nValue .= "'" . $ntmp[0] . "',";
                    break;
                case 'web_spider_enable':
                    $nField .= 'spider_enable' . ",";
                    $nValue .= "'" . $v . "',";
                    break;
                case 'web_thread':
                    $nField .= 'thread' . ",";
                    $nValue .= "'" . $v . "',";
                    break;
                case 'web_url_count':
                    $nField .= 'url_count' . ",";
                    $nValue .= "'" . $v . "',";
                    break;
                case 'web_timeout':
                    $nField .= 'timeout' . ",";
                    $nValue .= "'" . $v . "',";
                    break;
                case 'web_domain_timeout':
                    $nField .= 'domain_timeout' . ",";
                    $nValue .= "'" . $v . "',";
                    break;
                case 'web_exp_try_times':
                    $nField .= 'try_times' . ",";
                    $nValue .= "'" . $v . "',";
                    break;
                case 'web_exp_try_interval':
                    $nField .= 'conn_interval' . ",";
                    $nValue .= "'" . $v . "',";
                    break;
                case 'web_policy':
                    $nField .= 'policy' . ",";
                    $nValue .= "'" . $v . "',";
                    break;
                case 'web_status':
                    $nField .= 'status' . ",";
                    $nValue .= "'" . $v . "',";
                    break;
            }
        }

        $sField = rtrim($sField, ",");
        $sValue = rtrim($sValue, ",");
        //新增操作
        if ($sRows['port_enable'] == 0) {   //快速扫描
            $base = "daba56c8-73ec-11df-a475-002264764cea";
        } elseif ($sRows['port_enable'] == 1) {  //完全扫描
            $base = "708f25c4-7489-11df-8094-002264764cea";
        }

        $task_uuid = $sRows['task_uuid'];
        $target_uuid = $task_uuid;
        $addr = $target;
        $port_uuid = $db->result_first("SELECT port_uuid FROM port_manage where id =" . $sRows['port_policy']);

        if (!empty($sRows['weak_policy'])) {
            //$weak_uuid = $db->result_first("SELECT weak_uuid FROM weak_policy where id =" . $sRows['weak_policy']);
        } else {
            $weak_uuid = "--";
        }
        if (!empty($a_schedule)) {    //定时执行开启
            $schname = $task_uuid;
            $schhour = $a_schedule['hour'];
            $schminute = $a_schedule['minute'];
            $schday = $a_schedule['day_of_month'];
            $schmonth = $a_schedule['month'];
            $schperiod = $a_schedule['period'];
            if (empty($schperiod)) {
                $schperiod = "0";
            }
            $schperiodunit = $a_schedule['periodunit'];
            $schyear = $a_schedule['year'];
            $schon = 1;
        } else {      //定时执行关闭
            $schname = "--";
            $schhour = "00";
            $schminute = "00";
            $schday = "01";
            $schmonth = "01";
            $schperiod = "0";
            $schperiodunit = "hour";
            $schyear = "2015";
            $schon = 0;
        }

        if (!empty($sRows['host_policy'])) {  //如果选择主机策略
            $taskaccr_gets = $db->fetch_first("SELECT `accrtype`,`accrsmb`,`accrkerberos` FROM host_policy where id=" . $sRows['host_policy']);
            //var_dump($taskaccr_gets);die;
            $taskaccrtype = $taskaccr_gets['accrtype'];
            if (!empty($taskaccrtype) && $taskaccrtype > 0) {     //有帐号信息
                $taskaccrsmb = $taskaccr_gets['accrsmb'];
                $taskaccrkerberos = $taskaccr_gets['accrkerberos'];
                $taskaccrname = $task_uuid;
                $db->query("INSERT INTO s_task_accr (taskname,accrtype,accrsmb,accrkerberos) VALUES ('" . $taskaccrname . "',$taskaccrtype,'" . $taskaccrsmb . "','" . $taskaccrkerberos . "') ");
            }

            if ($sRows['port_enable'] == 0) {   //快速扫描
                $host_uuid = $db->result_first("SELECT `host_uuid` FROM host_policy where preset=1 limit 1 ");
            } else {
                $host_uuid = $db->result_first("SELECT host_uuid FROM host_policy where id =" . $sRows['host_policy']);
            }
        } else {  //如果没有选择主机策略
            if ($sRows['port_enable'] == 0) {   //快速扫描
                $host_uuid = $db->result_first("SELECT `host_uuid` FROM host_policy where preset=1 limit 1 ");
                $host_enable = '1';
            } else {
                $host_uuid = "--";
            }
        }
       //dl("openvas.so");
        //vas_bd_initialize(INTERFACE_ROOT, 9390);//echo 1;die;
        //$backcreateport = vas_bd_addtask($task_uuid, $target_uuid,$addr,$port_uuid,$host_uuid,$weak_uuid,$schname,$schhour,$schminute,$schday,$schmonth,$schperiod,$schperiodunit,$schyear,$schon,$host_enable,$weak_enable);      //返回1则创建成功
        //$sql = "INSERT INTO task_manage (" . $sField . ") VALUES (" . $sValue . ")";
        $sql="insert into task_manage set action=1,task_uuid='".uuid()."',type=$type";
        //echo $sql;die;
        //if($backcreateport==1){     //创建成功
        if (1) {
            if ($db->query($sql)) {
                $insert_id = $db->insert_id();
                $nField .= 'task_id' . ",";
                $nValue .= "'" . $insert_id . "',";
                $nField = rtrim($nField, ",");
                $nValue = rtrim($nValue, ",");
                if($sPost['web_enable']==1){
                    $nsql = "INSERT INTO bd_web_task (" . $nField . ") VALUES (" . $nValue . ")";
                    $db->query($nsql);
                }elseif($sPost['weak_enable']==1){
                    $uuid=$this->create_guid();
                    $name=
                    $nsql = "INSERT INTO bd_weakpwd_task_manage (uuid,name,target,thread,policy,timeout,status) VALUES ($uuid,)";

                    $db->query($nsql);
                }

//var_dump($insert_id);die;
                /*if($sRows['web_enable']==1) {
                //表bd_web_task
                //新增
                $webRows['task_id'] = $insert_id;
                $wField = "";
                $wValue = "";
                foreach ($webRows as $k => $v) {
                    $wField .= $k . ",";
                    $wValue .= "'" . $v . "',";
                }
                $wField = rtrim($wField, ",");
                $wValue = rtrim($wValue, ",");
                $sql = "INSERT INTO bd_web_task (" . $wField . ") VALUES (" . $wValue . ")";
                $db->query($sql);
            }*/
                if (intval($sPost['ifTemplate']) == 1) {    //保存为模板
                    $stRows = $sRows;
                    unset($stRows['task_name']);
                    unset($stRows['task_uuid']);
                    unset($stRows['web_target']);
                    unset($stRows['host_status']);
                    unset($stRows['task_status']);
                    unset($stRows['host_progress']);
                    unset($stRows['ipnum']);
                    unset($stRows['web_target']);
                    $stRows['template_name'] = filterStr($sPost['template_name']);
                    $stRows['template_remarks'] = filterStr($sPost['template_remarks']);
                    $stField = "";
                    $stValue = "";
                    foreach ($stRows as $k => $v) {
                        $stField .= $k . ",";
                        $stValue .= "'" . $v . "',";
                    }
                    $stField = rtrim($stField, ",");
                    $stValue = rtrim($stValue, ",");
                    $stql = "INSERT INTO template_manage (" . $stField . ") VALUES (" . $stValue . ")";
                    $db->query($stql);
                }
                //task_manage
                /*$task_managesql = "select count(*) from task_manage where task_uuid =".$task_uuid;
            $task_managecount = $db->result_first($task_managesql);
            if($task_managecount){

            }*/

               // $backcreateport = vas_bd_addtask($task_uuid, $target_uuid, $addr, $port_uuid, $host_uuid, $weak_uuid, $schname, $schhour, $schminute, $schday, $schmonth, $schperiod, $schperiodunit, $schyear, $schon, $host_enable, $weak_enable);      //返回1则创建成功

                if (1) {
                    $success = true;
                    $msg = "新增扫描任务成功";
                    $hdata['sDes'] = '新增扫描任务(' . $task_name . ')';
                    $hdata['sRs'] = "成功";
                    $hdata['sAct'] = $act . '/' . $show;
                    saveOperationLog($hdata);
                    $data['success'] = $success;
                    $data['msg'] = $msg;
                    echo json_encode($data);
                    exit;
                } else {
                    $success = false;
                    $msg = "新增扫描任务失败";
                    $hdata['sDes'] = '新增扫描任务(' . $task_name . ')';
                    $hdata['sRs'] = "失败";
                    $hdata['sAct'] = $act . '/' . $show;
                    saveOperationLog($hdata);
                    $data['success'] = $success;
                    $data['msg'] = $msg;
                    echo json_encode($data);
                    exit;
                }

            } else {
                $success = false;
                $msg = "新增扫描任务失败";
                $hdata['sDes'] = '新增扫描任务(' . $task_name . ')';
                $hdata['sRs'] = "失败";
                $hdata['sAct'] = $act . '/' . $show;
                saveOperationLog($hdata);
                $data['success'] = $success;
                $data['msg'] = $msg;
                echo json_encode($data);
                exit;
            }
        } else {
            $success = false;
            $msg = "后台创建任务失败";
            $data['success'] = $success;
            $data['msg'] = $msg;
            echo json_encode($data);
            exit;
        }
    }

    //编辑任务
     function editTask($sRows,$icount,$i_count,$target,$task_name){
         global $db,$act,$show;
         $iTotal = $db->result_first("SELECT COUNT(`task_name`) as num FROM task_manage where task_name='" . $sRows['task_name'] . "' And id !=" . $id);
         if (!empty($iTotal)) {
             $data['success'] = false;
             $data['msg'] = $sRows['task_name'] . '已存在，请更换';
             echo json_encode($data);exit;
         }
         $sRows['ipnum'] = $icount;
         $ipnum = $db->result_first("SELECT ipnum FROM bd_sys_sysinfo ");
         $ipnum = intval($ipnum);
         if ($ipnum != 0 && $ipnum != -1) {
             $totalipnum = $db->result_first("SELECT SUM(`ipnum`) num FROM task_manage WHERE id !=" . $id);
             $avaliatenum = $ipnum - intval($totalipnum);
             if ($i_count > $avaliatenum) {
                 $data['success'] = false;
                 $data['msg'] = '可扫描IP数量不能超过'.$ipnum.'（' . $totalipnum . '）';
                 echo json_encode($data);exit;
             }
         }
         $sFieldValue = "";
         $nFieldValue = "";
         foreach ($sRows as $k => $v) {
             if ($k == 'web_status') {
                 $sFieldValue .= $k . "= 2,";
             } else {
                 $sFieldValue .= $k . "= '" . $v . "',";
             }
             switch ($k) {
                 case 'task_name':
                     $nFieldValue .= $k . "= '" . $v . "',";
                     break;
                 case 'target':
                     $tmp = explode('##', $v);
                     $nFieldValue .= $k . "= '" . $tmp[0] . "',";
                     break;
                 case 'web_status':
                     $nFieldValue .= 'status' . "= 2,";
                     break;
                 case 'web_spider_enable':
                     $nFieldValue .= 'spider_enable' . "= '" . $v . "',";
                     break;
                 case 'web_thread':
                     $nFieldValue .= 'thread' . "= '" . $v . "',";
                     break;
                 case 'web_policy':
                     $nFieldValue .= 'policy' . "= '" . $v . "',";
                     break;
                 case 'web_url_count':
                     $nFieldValue .= 'url_count' . "= '" . $v . "',";
                     break;
                 case 'web_timeout':
                     $nFieldValue .= 'timeout' . "= '" . $v . "',";
                     break;
                 case 'web_domain_timeout':
                     $nFieldValue .= 'domain_timeout' . "= '" . $v . "',";
                     break;
                 case 'web_exp_try_times':
                     $nFieldValue .= 'try_times' . "= '" . $v . "',";
                     break;
                 case 'web_exp_try_interval':
                     $nFieldValue .= 'conn_interval' . "= '" . $v . "',";
                     break;
             }
         }
         $sFieldValue = rtrim($sFieldValue, ",");
         $nFieldValue = rtrim($nFieldValue, ",");
         $task_uuid = $db->result_first("SELECT task_uuid FROM task_manage where id =" . $id);
         $target_uuid = $task_uuid;
         $addr = $target;
         //var_dump($sRows);die;
         $port_uuid = $db->result_first("SELECT port_uuid FROM port_manage where id =" . $sRows['port_policy']);
         if (!empty($sRows['weak_policy'])) {
             $weak_uuid = $db->result_first("SELECT weak_uuid FROM weak_policy where id =" . $sRows['weak_policy']);
         } else {
             $weak_uuid = "--";
         }
         if (!empty($a_schedule)) {    //定时执行开启
             $schname = $task_uuid;
             $schhour = $a_schedule['hour'];
             $schminute = $a_schedule['minute'];
             $schday = $a_schedule['day_of_month'];
             $schmonth = $a_schedule['month'];
             $schperiod = $a_schedule['period'];
             if (empty($schperiod)) {
                 $schperiod = "0";
             }
             $schperiodunit = $a_schedule['periodunit'];
             $schyear = $a_schedule['year'];
             $schon = 1;
         } else {      //定时执行关闭
             $schname = "--";
             $schhour = "00";
             $schminute = "00";
             $schday = "01";
             $schmonth = "01";
             $schperiod = "0";
             $schperiodunit = "hour";
             $schyear = "2016";
             $schon = 0;
         }

         if (!empty($sRows['host_policy'])) {  //如果选择主机策略
             $taskaccr_gets = $db->fetch_first("SELECT `accrtype`,`accrsmb`,`accrkerberos` FROM host_policy where id=" . $sRows['host_policy']);
             $taskaccrtype = $taskaccr_gets['accrtype'];
             $taskaccrsmb = $taskaccr_gets['accrsmb'];
             $taskaccrkerberos = $taskaccr_gets['accrkerberos'];
             $taskaccrname = $task_uuid;
             if (!empty($taskaccrtype) && $taskaccrtype > 0) {     //有帐号信息
                 $taskid = $db->result_first("SELECT `id` FROM s_task_accr where taskname='" . $taskaccrname . "'");
                 if ($taskid) {    //数据库中已经存在，则更新
                     $db->query("UPDATE s_task_accr SET accrtype=$taskaccrtype, accrsmb='" . $taskaccrsmb . "', accrkerberos='" . $taskaccrkerberos . "' WHERE taskname='" . $taskaccrname . "' ");
                 } else {      //数据库中不存在，则添加
                     $db->query("INSERT INTO s_task_accr (taskname,accrtype,accrsmb,accrkerberos) VALUES ('" . $taskaccrname . "',$taskaccrtype,'" . $taskaccrsmb . "','" . $taskaccrkerberos . "') ");
                 }
             } else {      //无帐号信息
                 $taskid = $db->result_first("SELECT `id` FROM s_task_accr where taskname='" . $taskaccrname . "'");
                 if ($taskid) {    //数据库中已经存在，则删除
                     $db->query("DELETE FROM s_task_accr WHERE taskname='" . $taskaccrname . "'");
                 }
             }

             if ($sRows['port_enable'] == 0) {   //快速扫描
                 $host_uuid = $db->result_first("SELECT `host_uuid` FROM host_policy where preset=1 limit 1 ");
             } else {
                 $host_uuid = $db->result_first("SELECT host_uuid FROM host_policy where id =" . $sRows['host_policy']);
             }
         } else {  //如果没有选择主机策略
             $taskaccrname = $task_uuid;
             $taskid = $db->result_first("SELECT `id` FROM s_task_accr where taskname='" . $taskaccrname . "'");
             if ($taskid) {    //数据库中已经存在，则删除
                 $db->query("DELETE FROM s_task_accr WHERE taskname='" . $taskaccrname . "'");
             }
             if ($sRows['port_enable'] == 0) {   //快速扫描
                 $host_uuid = $db->result_first("SELECT `host_uuid` FROM host_policy where preset=1 limit 1 ");
                 $host_enable = '1';
             } else {
                 $host_uuid = "--";
             }
         }
         dl("openvas.so");

         vas_bd_initialize(INTERFACE_ROOT, 9390);
         //$backcreateport = vas_bd_edittask($task_uuid, $target_uuid,$addr,$port_uuid,$host_uuid,$weak_uuid,$schname,$schhour,$schminute,$schday,$schmonth,$schperiod,$schperiodunit,$schyear,$schon,$host_enable,$weak_enable);      //返回1则编辑成功
         vas_bd_deletetasks($task_uuid);
         //echo 'fsdf';die;
         $sql = "UPDATE task_manage SET " . $sFieldValue . " WHERE id=" . $id;
         $sql_n = "UPDATE bd_web_task SET " . $nFieldValue . " WHERE task_id=" . $id;
         $db->query($sql_n);
         //if($backcreateport==1){     //1: 编辑成功
         if (1) {
             //echo $sql;die;
             if ($db->query($sql)) {
                 //编辑成功的话，时间设置1
                 $timesql = "update task_manage set start_time = 1 ,end_time =1,task_status=2,task_startstate=2 where id = " . $id;
                 $timesql_n = "update bd_web_task set start_time = 1 ,end_time =1,status='2' where task_id = " . $id;
                 $db->query($timesql);
                 $db->query($timesql_n);
                 /*if($sRows['web_enable']==1){
                 //更新表bd_web_task
                 $wFieldValue = "";
                 foreach($webRows as $k=>$v){
                     $wFieldValue .= $k . "= '" .$v. "',";
                 }
                 $wFieldValue = rtrim($wFieldValue, ",");
                 $sql = "UPDATE bd_web_task SET ".$wFieldValue." WHERE task_id=".$id;
                 $db->query($sql);
             }*/
                 //
                 $backcreateport = vas_bd_addtask($task_uuid, $target_uuid, $addr, $port_uuid, $host_uuid, $weak_uuid, $schname, $schhour, $schminute, $schday, $schmonth, $schperiod, $schperiodunit, $schyear, $schon, $host_enable, $weak_enable);      //返回1则编辑成功
                 //var_dump($backcreateport);die;
                 if ($backcreateport == 1) {
                     $success = true;
                     $msg = "编辑成功";
                     $hdata['sDes'] = '编辑扫描任务(' . $task_name . ')';
                     $hdata['sRs'] = "成功";
                     $hdata['sAct'] = $act . '/' . $show;
                     saveOperationLog($hdata);
                 } else {
                     $success = false;
                     $msg = "编辑失败";
                     $hdata['sDes'] = '编辑扫描任务(' . $task_name . ')';
                     $hdata['sRs'] = "失败";
                     $hdata['sAct'] = $act . '/' . $show;
                     saveOperationLog($hdata);
                 }
             } else {
                 $success = false;
                 $msg = "编辑失败";
                 $hdata['sDes'] = '编辑任务(' . $task_name . ')';
                 $hdata['sRs'] = '失败';
                 $hdata['sAct'] = $act . '/' . $show;
                 saveOperationLog($hdata);
             }
         } else {
             $success = false;
             $msg = "后台编辑任务失败";
             $hdata['sDes'] = '后台编辑任务(' . $task_name . ')';
             $hdata['sRs'] = '失败';
             $hdata['sAct'] = $act . '/' . $show;
             saveOperationLog($hdata);
         }
         $data['success'] = $success;
         $data['msg'] = $msg;
         echo json_encode($data);exit;
     }


    //创建唯一id
    function create_guid()
    {
        $charid = strtoupper(md5(uniqid(mt_rand(), true)));
        $hyphen = "";//chr(45);
        $uuid = //chr(123)
            substr($charid, 0, 8) . $hyphen
            . substr($charid, 8, 4) . $hyphen
            . substr($charid, 12, 4) . $hyphen
            . substr($charid, 16, 4) . $hyphen
            . substr($charid, 20, 12);
        //.chr(125);
        return $uuid;
    }

    /**
     * @ 从数据库中删除数据
     * @ params $id
     */
    function actionDel()
    {
        if(!empty($_POST['ids'])){
            foreach (explode(',',$_POST['ids']) as $k=>$v){
              //  var_dump($v);
                $vv=explode(':',$v);
                if($vv[1]=='weakpwd'){
                    Yii::$app->db->createCommand("delete from bd_weakpwd_task_manage where uuid='$vv[0]'")->execute();
                    Yii::$app->db->createCommand("delete from bd_weakpwd_history where uuid='$vv[0]'")->execute();
                    $table="bd_weakpwd_result_$vv[2]";
                }elseif($vv[1]=='web'){
                    Yii::$app->db->createCommand("delete from bd_web_task_manage where uuid='$vv[0]'")->execute();
                    $table="bd_web_result_$vv[2]";
                }else{
                    $table="bd_host_result_$vv[2]";
                    Yii::$app->db->createCommand("delete from bd_host_task_manage where uuid='$vv[0]'")->execute();
                }
                if(in_array($table,$this->getAllTables())){
                    Yii::$app->db->createCommand("drop table $table")->execute();
                }
            }
        }
        saveOperationLog(['sRs'=>'删除任务','sAct'=>Yii::$app->request->getUrl()]);
        $data['success'] = true;
        $data['msg'] = '删除成功';
        echo json_encode($data);
        exit;
    }


    /**
     * 任务详情
     * @ 获取任务状态
     */
    function actionTaskdetailstate()
    {
        global $db;
        $sPost = $_REQUEST;
        $rows1 = array();
        $rows2 = array();
        $rows3 = array();
        $rows = array();
        $taskid = intval($sPost['taskid']);
        $page = intval($sPost['start']);
        $perpage = intval($sPost['length']);
        $type = ($sPost['type']);
        $total = 0;
        $where = " WHERE 1=1";
        $page = $page > 1 ? $page : 1;
        $alltables = $this->getAllTables();
        $findhosttable = "bd_host_result_" . $taskid;
        $i = 0;
        if (in_array($findhosttable, $alltables) && ($type=='主机')) {
            //主机
            $iprows = $db->fetch_all("SELECT distinct ip FROM bd_host_result_" . $taskid . "  $where");
            foreach ($iprows as $k => $v) {
                $level = $db->fetch_all("SELECT vul_level as level, count(vul_level) as rNum FROM bd_host_result_" . $taskid . " WHERE  ip='" . $v['ip'] . "' GROUP BY vul_level");
                $hlevel = $this->getLevel($level);
                $r_flag = false;
                foreach ($level as $k2 => $v2) {
                    if ($v2['rNum'] > 0) {
                        $rows1[$i][$v2['level']] = $v2['rNum'];
                        $r_flag = true;
                    }

                }
                if ($r_flag) {
                    $rows1[$i]['group'] = "主机扫描结果";
                    $rows1[$i]['category'] = "HOST";
                    $rows1[$i]['ip'] = $v['ip'];
                    $rows1[$i]['domain_title'] = 'HOST';
                    $rows1[$i]['risk_factor'] = $hlevel;
                    $i++;
                }

            }
            //主机漏洞排序
            $num1 = "";
            $num2 = "";
            $num3 = "";
            $num7 = "";
            foreach ($rows1 as $key => $row) {
                if (empty($row['H'])) {
                    $num1[$key] = 0;
                } else {
                    $num1[$key] = $row ['H'];
                }
                if (empty($row['M'])) {
                    $num2[$key] = 0;
                } else {
                    $num2[$key] = $row ['M'];
                }
                if (empty($row['L'])) {
                    $num3[$key] = 0;
                } else {
                    $num3[$key] = $row ['L'];
                }
                if (empty($row['I'])) {
                    $num7[$key] = 0;
                } else {
                    $num7[$key] = $row ['I'];
                }
            }
            array_multisort($num1, SORT_DESC, $num2, SORT_DESC, $num3, SORT_DESC, $num7, SORT_DESC, $rows1);
            if (!empty($rows1)) {
                foreach ($rows1 as $k => $v) {
                    array_push($rows, $v);
                }
            }
        }

        $findwebtable = "bd_web_result_" . $taskid;
        //$wlevel = array(4=>'H',3=>'M',2=>'L',5=>'I');
        if (in_array($findwebtable, $alltables) && ($type=='web')) {
            //web
            $webiprows = $db->fetch_all("SELECT distinct `domain` FROM bd_web_result_" . $taskid . " WHERE 1=1");
            foreach ($webiprows as $k1 => $v1) {
                $level = $db->fetch_all("SELECT `level`, count(`level`) as iNum FROM bd_web_result_" . $taskid . " WHERE 1=1 AND domain='" . $v1['domain'] . "' GROUP BY level");
                $hlevel = $this->getLevel($level);

                $i_flag = false;
                foreach ($level as $k2 => $v2) {
                    if ($v2['iNum'] > 0) {
                        $rows2[$i][$v2['level']] = $v2['iNum'];
                        $i_flag = true;

                    }
                }
                if ($i_flag) {
                    $rows2[$i]['group'] = "WEB扫描结果";
                    $rows2[$i]['category'] = "WEB";
                    $rows2[$i]['ip'] = $v1['domain'];
                    $rows2[$i]['domain_title'] = "WEB";
                    $rows2[$i]['risk_factor'] = $hlevel;
                    $i++;
                }

            }
            $num4 = "";
            $num5 = "";
            $num6 = "";
            $num8 = "";
            foreach ($rows2 as $key => $row) {
                if (empty($row['H'])) {
                    $num4[$key] = 0;
                } else {
                    $num4[$key] = $row ['H'];
                }
                if (empty($row['M'])) {
                    $num5[$key] = 0;
                } else {
                    $num5[$key] = $row ['M'];
                }
                if (empty($row['L'])) {
                    $num6[$key] = 0;
                } else {
                    $num6[$key] = $row ['L'];
                }
                if (empty($row['I'])) {
                    $num8[$key] = 0;
                } else {
                    $num8[$key] = $row ['I'];
                }
            }
            array_multisort($num4, SORT_DESC, $num5, SORT_DESC, $num6, SORT_DESC, $num8, SORT_DESC, $rows2);
            if (!empty($rows2)) {
                foreach ($rows2 as $k => $v) {
                    array_push($rows, $v);
                }
            }
        }

        $findwebtable = "bd_weakpwd_result_" . $taskid;
        //$wlevel = array(4=>'H',3=>'M',2=>'L');
        if (in_array($findwebtable, $alltables) && ($type=='弱密码')) {
            //web
            $webiprows = $db->fetch_all("SELECT distinct s.ip FROM bd_weakpwd_result_" . $taskid . " AS s  $where");
            foreach ($webiprows as $k1 => $v1) {
                $hnum = $db->result_first("SELECT COUNT(id) as h FROM bd_weakpwd_result_" . $taskid . " WHERE  ip='" . $v1['ip'] . "'");
                //$hlevel = getLevel($level);

                /*foreach($level as $k2=>$v2){
                $rows3[$i][$wlevel[$v2['level']]] = $v2['iNum'];
            }*/
                if ($hnum > 0) {
                    $rows3[$i]['H'] = $hnum;
                    $rows3[$i]['group'] = "弱密码扫描结果";
                    $rows3[$i]['category'] = "WEAK";
                    $rows3[$i]['ip'] = $v1['ip'];
                    $rows3[$i]['domain_title'] = "弱密码";
                    $rows3[$i]['risk_factor'] = 'H';//弱密码暂时写死为H
                    $i++;
                }

            }
            $num9 = "";
            $num10 = "";
            $num11 = "";
            $num12 = "";
            foreach ($rows3 as $key => $row) {
                if (empty($row['H'])) {
                    $num9[$key] = 0;
                } else {
                    $num9[$key] = $row ['H'];
                }
                if (empty($row['M'])) {
                    $num10[$key] = 0;
                } else {
                    $num10[$key] = $row ['M'];
                }
                if (empty($row['L'])) {
                    $num11[$key] = 0;
                } else {
                    $num11[$key] = $row ['L'];
                }
                if (empty($row['I'])) {
                    $num12[$key] = 0;
                } else {
                    $num12[$key] = $row ['I'];
                }
            }
            array_multisort($num9, SORT_DESC, $num10, SORT_DESC, $num11, SORT_DESC, $num12, SORT_DESC, $rows3);
            if (!empty($rows3)) {
                foreach ($rows3 as $k => $v) {
                    array_push($rows, $v);
                }
            }
        }

        $data = array();
        if (count($rows) > 0) {
            for ($i = ($page - 1) * $perpage; $i < $page * $perpage; $i++) {
                if ($i >= count($rows)) break;
                array_push($data, $rows[$i]);
            }
        }

        $data['Rows'] = $data;
        $data['host_value'] = $rows1;
        $data['web_value'] = $rows2;
        $data['weak_value'] = $rows3;
        $data['Total'] = count($rows);
        echo json_encode($data);
        exit;
    }

    /*
 * 二维数组按指定键值排须
 */
    function arr_sort($array, $key, $order = "asc")
    {//asc是升序 desc是降序//按 I<L<M<H 排序

        $arr_nums = $arr = array();

        foreach ($array as $k => $v) {

            $arr_nums[$k] = $v[$key];

        }

        if ($order == 'asc') {

            uasort($arr_nums, 'my_sort_asc');

        } else {

            uasort($arr_nums, 'my_sort_desc');

        }

        foreach ($arr_nums as $k => $v) {

            $arr[$k] = $array[$k];

        }

        return $arr;

    }

    function my_sort_desc($a, $b)
    {
        if ($a == $b) return 0;
        if ($a == 'I' && $b != 'I') return 1;
        if ($a == 'L' && $b != 'I') return 1;
        if ($a == 'L' && $b == 'I') return -1;
        if ($a == 'M' && $b != 'H') return -1;
        if ($a == 'M' && $b == 'H') return 1;
        if ($a == 'H' && $b != 'H') return -1;
    }

    function my_sort_asc($a, $b)
    {
        if ($a == $b) return 0;
        if ($a == 'I' && $b != 'I') return -1;
        if ($a == 'L' && $b != 'I') return -1;
        if ($a == 'L' && $b == 'I') return 1;
        if ($a == 'M' && $b != 'H') return 1;
        if ($a == 'M' && $b == 'H') return -1;
        if ($a == 'H' && $b != 'H') return 1;
    }

    /**
     * 获取任务扫描结果的相关主机漏洞
     */
    function actionGethostvul()
    {
        global $db;
        $sPost = $_POST;
        $rows = array();
        $rowtable = array();
        $aData = array();
        $taskid = intval($sPost['taskid']);
        $where = " WHERE 1=1";
        $findtable = "bd_host_result_" . $taskid;
        $alltables = $this->getAllTables();
        $key_s = filterStr($sPost['key_s']);
        $term_key = filterStr($sPost['term_key']);
        //print_r($sPost);
        //print_r(!empty($key_s));
        if (!empty($key_s)) {
            //print_r($term_key);
            if ($term_key == 'ip') {
                $where = " WHERE ip = '$key_s'";
            }
            if ($term_key == 'theme') {
                //print_r($sPost);
                $where = " WHERE vul_name LIKE '%$key_s%'";
            }
            if ($term_key == 'level') {
                $where = " WHERE vul_level = '$key_s'";
            }
        }
        //print_r($where);
        if (in_array($findtable, $alltables)) {//echo 1;die;
            $rows = $db->fetch_all("SELECT `vul_name`,`family`,`vul_level`,`description`,`solution` FROM $findtable $where  GROUP BY vul_name");
            //print_r($rows);exit;
            $rows = $this->arr_sort($rows, 'vul_level', $order = "desc");
            foreach ($rows as $k => $v) {
                $vulname = $v['vul_name'];
                $vulname = addslashes($vulname);
                $rowips = $db->fetch_all("SELECT `ip`,`vul_name`,`family`,`port_proto`,`vul_level`,`description`,`solution` FROM $findtable
            WHERE vul_name='" . $vulname . "' ");
                $bd = "";
                if ($v['vul_level'] == "H") {
                    $bd = "/resource/skin/blue/images/h_level.png";
                } elseif ($v['vul_level'] == "M") {
                    $bd = "/resource/skin/blue/images/m_level.png";
                } elseif ($v['vul_level'] == "L") {
                    $bd = "/resource/skin/blue/images/l_level.png";
                } elseif ($v['vul_level'] == "I") {
                    $bd = "/resource/skin/blue/images/i_level.png";
                }
                $ips = "";
                $aData1 = array();
                foreach ($rowips as $k1 => $v1) {
                    if ($v1['vul_name'] != null) {
                        if ($v1['port_proto'] == '') {
                            //   $ips = $ips . $v1['ip'];
                            $ips = $v1['ip'];
                        } else {
                            $ips = $v1['ip'] . "[" . $v1['port_proto'] . "]";
                        }
                        $aItem1 = array(
                            "ilevel" => 3,
                            "name" => $ips,
                            "vul_name" => $v1['vul_name'],
                            "family" => $v1['family'],
                            "risk_factor" => $v1['vul_level'],
                            "output" => '',
                            "desc" => $v1['description'],
                            "solution" => $v1['solution'],
                            "reflect" => $ips
                        );
                        array_push($aData1, $aItem1);
                    }

                }
                if ($v['vul_name'] != null) {
                    $aItem = array(
                        "open" => false,
                        "ilevel" => 2,
                        "name" => $v['vul_name'],
                        "vul_name" => $v['vul_name'],
                        "family" => $v['family'],
                        "risk_factor" => $v['vul_level'],
                        "output" => '',
                        "desc" => $v['description'],
                        "solution" => $v['solution'],
                        "reflect" => $ips,
                        "icon" => is_null($bd) ? "" : $bd,
                        "children" => $aData1
                    );
                    array_push($aData, $aItem);
                }

            }
        }

        $tData = array(
            "open" => true,
            "ilevel" => 1,
            "name" => "主机漏洞",
            "children" => $aData
        );

        echo json_encode($tData);
        exit;
    }

    /**
     * 获取任务扫描结果的相关web漏洞
     */
    function actionGetwebvul()
    {
        global $db;
        $sPost = $_POST;
        $rows = array();
        $aData = array();
        $taskid = intval($sPost['taskid']);
        $where = " WHERE 1=1";
        $findtable = "bd_web_result_" . $taskid;
        $alltables = $this->getAllTables();
        $key_s = filterStr($sPost['key_s']);
        $term_key = filterStr($sPost['term_key']);
        if (!empty($key_s)) {
            if ($term_key == 'ip') {
                $ipwhere = " AND ip = '$key_s'";
            }
            if ($term_key == 'theme') {
                $where = " WHERE vul_name LIKE '%$key_s%'";
            }
            if ($term_key == 'level') {
                $where = " WHERE level = '$key_s'";
            }
        }
        if (in_array($findtable, $alltables)) {
            $rows = $db->fetch_all("SELECT `vul_name`,`level`,`description`,`solution` FROM bd_web_result_" . $taskid . $where . " GROUP BY vul_name");
            $rows = $this->arr_sort($rows, 'level', $order = "desc");
            foreach ($rows as $k => $v) {
                $vulname = $v['vul_name'];
                $vulname = addslashes($vulname);
                $rowips = $db->fetch_all("SELECT `ip`,`url`,`vul_name`,`level`,`description`,`solution` FROM bd_web_result_" . $taskid . "  WHERE vul_name='" . $vulname . "'$ipwhere ");
                $bd = "";
                if ($v['level'] == 'H') {
                    $bd = "/resource/skin/blue/images/h_level.png";
                } else if ($v['level'] == 'M') {
                    $bd = "/resource/skin/blue/images/m_level.png";
                } else if ($v['level'] == 'L') {
                    $bd = "/resource/skin/blue/images/l_level.png";
                } else if ($v['level'] == 'I') {
                    $bd = "/resource/skin/blue/images/i_level.png";
                }
                $urls = "";
                $aData1 = array();
                foreach ($rowips as $k1 => $v1) {
                    if ($v1['vul_name'] != null) {
                        $urls = $urls . $v1['url'] . ", ";
                        $aItem1 = array(
                            "ilevel" => 3,
                            "name" => $v1['url'],
                            "vul_name" => $v1['vul_name'],
                            "risk_factor" => $v1['level'],
                            "detail" => $v1['description'],
                            "solu" => $v1['solution'],
                            "reflect" => $v1['url']
                        );
                        array_push($aData1, $aItem1);
                    }

                }
                if ($v['vul_name'] != null) {
                    $aItem = array(
                        "open" => false,
                        "ilevel" => 2,
                        "name" => $v['vul_name'],
                        "vul_name" => $v['vul_name'],
                        "risk_factor" => $v['level'],
                        "detail" => $v1['description'],
                        "solu" => $v1['solution'],
                        "reflect" => $urls,
                        "icon" => is_null($bd) ? "" : $bd,
                        "children" => $aData1
                    );
                    array_push($aData, $aItem);
                }

            }
        }
        $tData = array(
            "open" => true,
            "ilevel" => 1,
            "name" => "WEB漏洞",
            "children" => $aData
        );
        echo json_encode($tData);
        exit;
    }

    /**
     * 获取任务扫描结果的相关弱密码漏洞
     */
    function actionGetweakvul()
    {
        global $db;
        $sPost = $_POST;
        $aData = array();
        $taskid = intval($sPost['taskid']);
        $findtable = "bd_weakpwd_result_" . $taskid;
        $alltables = $this->getAllTables();
        if (in_array($findtable, $alltables)) {
            $rows = $db->fetch_all("SELECT distinct `vul_name`,`dbname`,`username`,`password`,`vul_id` FROM bd_weakpwd_result_" . $taskid . "  WHERE task_id = " . $taskid);
            foreach ($rows as $k => $v) {
                $rowips = $db->fetch_all("SELECT `vul_name`,`dbname`,`username`,`password`,`ip`,`proto`,`port`,'vul_id' FROM bd_weakpwd_result_" . $taskid . "  WHERE task_id = " . $taskid . " and vul_id =" . $v['vul_id'] . " and username = '" . $v['username'] . "' and password ='" . $v['password'] . "'");
                $sTotal = count($rowips);
                $aData1 = array();
                foreach ($rowips as $k1 => $v1) {
                    if ($v1['ip'] != null) {
                        $aItem1 = array(
                            "ilevel" => 3,
                            "name" => $v1['ip'] . " [" . $v1['proto'] . " / " . $v1['port'] . "]",
                        );
                        array_push($aData1, $aItem1);
                    }
                }
                if ($v['vul_name'] == 'IBM_DB2弱密码') {
                    $aItem = array(
                        "open" => false,
                        "ilevel" => 2,
                        "name" => "类型：" . $v['vul_name'] . ", 数据库：" . $v['dbname'] . "，用户名：" . $v['username'] . "，密码：" . $v['password'] . "，[" . $sTotal . "]",
                        "risk_factor" => "H",
                        "icon" => "/resource/skin/blue/images/h_level.png",
                        "children" => $aData1
                    );
                } else {
                    $aItem = array(
                        "open" => false,
                        "ilevel" => 2,
                        "name" => "类型：" . $v['vul_name'] . "，用户名：" . $v['username'] . "，密码：" . $v['password'] . "，[" . $sTotal . "]",
                        "risk_factor" => "H",
                        "icon" => "/resource/skin/blue/images/h_level.png",
                        "children" => $aData1
                    );
                }
                array_push($aData, $aItem);
            }
        }

        $tData = array(
            "open" => true,
            "ilevel" => 1,
            "name" => "弱密码漏洞",
            "children" => $aData
        );

        echo json_encode($tData);
        exit;
    }


    /**
     * @ 获取所有的端口策略
     */
    function getportpolicy()
    {
        global $db;
        $rows = $db->fetch_all("SELECT * FROM port_manage WHERE 1=1 ");
        echo json_encode($rows);
        exit;
    }

    /**
     * @ 获取所有的主机策略
     */
    function gethostpolicy()
    {
        global $db;
        $rows = $db->fetch_all("SELECT * FROM host_policy ");
        echo json_encode($rows);
        exit;
    }

    /**
     * @ 获取所有的WEB策略
     */
    function getwebpolicy()
    {
        global $db;
        $rows = $db->fetch_all("SELECT * FROM bd_web_policy ");
        echo json_encode($rows);
        exit;
    }

    /**
     * @ 获取所有的弱密码策略
     */
    function getweakpolicy()
    {
        global $db;
        $rows = $db->fetch_all("SELECT * FROM bd_weakpwd_policy ");
        echo json_encode($rows);
        exit;
    }
    

    function getLevel($levelarray)
    {
        $array = array();
        foreach ($levelarray as $k => $v) {
            $array[] = $v['level'];
        }
        if (in_array('H', $array)) {
            return 'H';
        }
        if (in_array('M', $array)) {
            return 'M';
        }
        if (in_array('L', $array)) {
            return 'L';
        }
        if (in_array('I', $array)) {
            return 'I';
        }
        return 'L';
    }

    /**
     * 获取所有的数据表
     * 返回一维数组： array
     */
    function getAllTables()
    {
        global $db;
        $tables = $db->fetch_all("show TABLES");
        foreach ($tables as $key => $value) {
            $rowtable[] = $value['Tables_in_security'];
        }
        return $rowtable;
    }

    /**
     * 漏洞风险图
     *
     */
    function actionRisklog()
    {
        global $db;
        if (isset($_POST['allTaskRisk'])) {
            $where = 'WHERE 1=1';
            $sql_f = "select report_time,num,h as H,m as M,l as L,i as I from `history_task_sum` $where";
        } else {
            $taskid = intval($_POST['taskid']);
            $where = "WHERE task_id=" . $taskid;
            $sql_f = "select report_time,num,h as H,m as M,l as L,i as I from `history_task` $where";
        }
        //1.风险级别区域
        //$sql_f = "select report_time,num,h as H,m as M,l as L,i as I from `history_task_sum` $where";
        $arr_f = $db->fetch_all($sql_f);
        if (!empty($arr_f)) {
            //var_dump($arr_f);
            $arr_d = array();
            foreach ($arr_f as $k => $val) {
                $val['R'] = $val['H'] > 0 ? '4' : ($val['M'] > 0 ? '3' : ($val['L'] > 0 ? '2' : '1'));//增加风险评估列的数据
                $val['time'] = $val['report_time'];
                $val = array_reverse($val);//翻转数组
                $arr_t[$k] = $val;
                $f_val = array_values($val);//返回值组成的新数组
                $arr_f[$k] = $f_val;
            }
            array_push($arr_d, $arr_f);
            $ttt = array_column($arr_t, 'R');//返回数组某一列的值
            $ddd = array_column($arr_t, 'report_time');
            array_push($arr_d, $ttt);
            array_push($arr_d, $ddd);
            //var_dump($arr_d);exit;
            $aJson['success'] = true;
            $aJson['zcdata'] = $arr_d;
        } else {
            $aJson['success'] = false;
            $aJson['zcdata'] = '没有相关风险结果';
        }
        //2.风险数目区域
        //$sql_f = "select report_time,num,h as H,m as M,l as L,i as I from `history_task` WHERE task_id=".$taskid;
        $arr_f = $db->fetch_all($sql_f);
        if (!empty($arr_f)) {
            //var_dump($arr_f);exit;
            $arr_d = $arr_t = array();
            foreach ($arr_f as $k => $val) {
                $val['R'] = $val['H'] > 0 ? '4' : ($val['M'] > 0 ? '3' : ($val['L'] > 0 ? '2' : '1'));//增加风险评估列的数据
                $val['time'] = $val['report_time'];
                $val = array_reverse($val);
                $arr_t[$k] = $val;
                $f_val = array_values($val);
                $arr_f[$k] = $f_val;
            }
            array_push($arr_d, $arr_f);
            $ttt = array_column($arr_t, 'R');
            $ddd = array_column($arr_t, 'report_time');
            array_push($arr_d, $ttt);
            array_push($arr_d, $ddd);
            //var_dump($arr_d);exit;
            $aJson['success'] = true;
            $aJson['zcsmdata'] = $arr_d;

        } else {
            $aJson['success'] = false;
            $aJson['zcsmdata'] = '没有相关风险结果';
        }
        echo json_encode($aJson);
        exit;
    }


    /*function in_allowip($ipArr,$CheckIp,$tag){
    if($tag==1){    // 检测ip
        foreach($ipArr as $v){
            if($CheckIp==$v){
                return true;
            }else{
                if( strpos($v, '-')){
                    $ips = explode('-',$v);
                    $ipfirst = intval(substr($ips[0], strrpos($ips[0], '.') + 1));
                    $iplast = intval(substr($ips[1], strrpos($ips[1], '.') + 1));
                    $ipChk = intval(substr($CheckIp, strrpos($CheckIp, '.') + 1));
                    if($ipChk>=$ipfirst &&  $ipChk<=$iplast){
                        $checkIp_arr = explode('.',$CheckIp);
                        $ips_first = explode('.',$ips[0]);
                        //不允许跨网段扫描
                        if($ips_first[0] == $checkIp_arr[0] && $ips_first[1] == $checkIp_arr[1] && $ips_first[2] == $checkIp_arr[2]){
                            return true;
                        }else{
                            return false;
                        }
                    }
                }
            }
        }
    }elseif($tag==2){   //检测ip段
        $chkArr = explode('-',$CheckIp);
        $chkipfirst = intval(substr($chkArr[0], strrpos($chkArr[0], '.') + 1));
        $chkiplast = intval(substr($chkArr[1], strrpos($chkArr[1], '.') + 1));
        foreach($ipArr as $v){
            $allowArr = explode('-',$v);
            $allowipfirst = intval(substr($allowArr[0], strrpos($allowArr[0], '.') + 1));
            $allowiplast = intval(substr($allowArr[1], strrpos($allowArr[1], '.') + 1));
            if($chkipfirst>=$allowipfirst && $chkiplast<=$allowiplast){
                return true;
            }
        }
    }
    return false;
}*/
    function in_allowip($ipArr, $CheckIp, $tag)
    {
        $return = false;
        if ($tag == 1) {    // 检测ip
            foreach ($ipArr as $v) {
                if ($CheckIp == $v) {
                    return true;
                } else {
                    if (strpos($v, '-')) {
                        $ips = explode('-', $v);
                        $ipfirst = intval(substr($ips[0], strrpos($ips[0], '.') + 1));
                        $iplast = intval(substr($ips[1], strrpos($ips[1], '.') + 1));
                        $ipChk = intval(substr($CheckIp, strrpos($CheckIp, '.') + 1));
                        if ($ipChk >= $ipfirst && $ipChk <= $iplast) {
                            $checkIp_arr = explode('.', $CheckIp);
                            $ips_first = explode('.', $ips[0]);
                            //不允许跨网段扫描
                            if ($ips_first[0] == $checkIp_arr[0] && $ips_first[1] == $checkIp_arr[1] && $ips_first[2] == $checkIp_arr[2]) {
                                return true;
                            } else {
                                $return = false;
                            }
                        }
                    }
                }
            }
        } elseif ($tag == 2) {   //检测ip段
            $chkArr = explode('-', $CheckIp);
            $chkipfirst = intval(substr($chkArr[0], strrpos($chkArr[0], '.') + 1));
            $chkiplast = intval(substr($chkArr[1], strrpos($chkArr[1], '.') + 1));
            foreach ($ipArr as $v) {
                $allowArr = explode('-', $v);
                $allowipfirst = intval(substr($allowArr[0], strrpos($allowArr[0], '.') + 1));
                $allowiplast = intval(substr($allowArr[1], strrpos($allowArr[1], '.') + 1));
                if ($chkipfirst >= $allowipfirst && $chkiplast <= $allowiplast) {
                    $checkIp_arr = explode('.', $chkArr[0]);
                    $ips_first = explode('.', $allowArr[0]);
                    //不允许跨网段扫描
                    if ($ips_first[0] == $checkIp_arr[0] && $ips_first[1] == $checkIp_arr[1] && $ips_first[2] == $checkIp_arr[2]) {
                        return true;
                    } else {
                        $return = false;
                    }
                }
            }
        }
        return $return;
    }

    function in_allowipv6($ipArr, $CheckIp, $tag)
    {
        if ($tag == 1) {    // 检测ip
            foreach ($ipArr as $v) {
                if ($CheckIp == $v) {
                    return true;
                } else {
                    if (strpos($v, '-')) {
                        $ips = explode('-', $v);
                        $ipfirst = intval(substr($ips[0], strrpos($ips[0], ':') + 1), 16);
                        $iplast = intval(substr($ips[1], strrpos($ips[1], ':') + 1), 16);
                        $ipChk = intval(substr($CheckIp, strrpos($CheckIp, ':') + 1), 16);
                        if ($ipChk >= $ipfirst && $ipChk <= $iplast) {
                            return true;
                        }
                    }
                }
            }
        } elseif ($tag == 2) {   //检测ip段
            $chkArr = explode('-', $CheckIp);
            $chkipfirst = intval(substr($chkArr[0], strrpos($chkArr[0], ':') + 1), 16);
            $chkiplast = intval(substr($chkArr[1], strrpos($chkArr[1], ':') + 1), 16);
            foreach ($ipArr as $v) {
                $allowArr = explode('-', $v);
                $allowipfirst = intval(substr($allowArr[0], strrpos($allowArr[0], ':') + 1), 16);
                $allowiplast = intval(substr($allowArr[1], strrpos($allowArr[1], ':') + 1), 16);
                if ($chkipfirst >= $allowipfirst && $chkiplast <= $allowiplast) {
                    return true;
                }
            }
        }
        return false;
    }

//把2001::1:200:7-20 处理为 2001::1:200:7-2001::1:200:20
    function ips_chuli2($v)
    {
        $a_target_str = explode("-", trim($v));
        if (count($a_target_str) == 2) {
            $sl = $a_target_str[0];
            $sr = $a_target_str[1];

            if (strpos($sl, '.') && !strpos($sr, '.')) {
                $sr = substr($sl, 0, (strrpos($sl, '.') + 1)) . $sr;
            } else if (strpos($sl, ':') && !strpos($sr, ':')) {
                $sr = substr($sl, 0, (strrpos($sl, ':') + 1)) . $sr;
            }
            $v = $sl . '-' . $sr;
        }
        return $v;
    }
    function ips_chuli($v)
    {
        $a_target_str = explode("-", trim($v));//var_dump($a_target_str);
        if (count($a_target_str) == 2) {
            $sl = $a_target_str[0];
            $sr = $a_target_str[1];
            $str1=$str2='';
            if (strpos($sl, '.') && !strpos($sr, '.')) {
//                for($i=explode('.',$sl)[3];$i<=$sr;$i++){
//                    $str1.=substr($sl, 0, (strrpos($sl, '.') + 1)).$i.',';
//                }
                $sr = substr($sl, 0, (strrpos($sl, '.') + 1)) . $sr;
            } else if (strpos($sl, ':') && !strpos($sr, ':')) {
                //echo 1;die;
//                for($i=explode(':',$sl)[2];$i<=$sr;$i++){
//                    $str2.=substr($sl, 0, (strrpos($sl, ':') + 1)).$i.',';
//                }
                $sr = substr($sl, 0, (strrpos($sl, ':') + 1)) . $sr;
            }
            $v = $sl.'-'.$sr;
        }
//        if(!empty($str1)){
//            $v = trim($str1,',');
//        }
//        if(!empty($str2)){
//            $v= trim($str2,',');
//        }
//var_dump(trim($str,','));die;
        return $v;

    }

//若IP格式不对，则返回false。否则返回true
    function filter_ip($ip)
    {
        if (strrpos($ip, '-')) {
            $ip_str = explode("-", trim($ip));
            $sl = $ip_str[0];
            $sr = $ip_str[1];
            if (!filter_var($sl, FILTER_VALIDATE_IP) || !filter_var($sr, FILTER_VALIDATE_IP))
                return false;
        } else {
            if (!filter_var($ip, FILTER_VALIDATE_IP))
                return false;
        }
        return true;
    }

    function GetHadsms()
    {
        global $db;
        $aData = array();
        $where = " WHERE 1=1 ";
        $userid = intval($_SESSION['userid']);
        $loginuser = $db->fetch_first("select role_id as  role from bd_sys_user WHERE id=$userid ");
        if ($loginuser['role'] != 16) { //不是系统管理员
            $where .= " AND user_id=$userid";
        }
        $rows = $db->fetch_all("SELECT * FROM task_manage  $where");
        foreach ($rows as $k => $v) {
            //未执行返回-2，已执行返回-1，正在执行返回0-100，暂停返回-3，停止返回-4 ,-6等待扫描，-7正在停止，-8正在暂停
            //if(($v['task_progress']>=0 && $v['task_progress']<=100)||$v['task_startstate']==-6||$v['task_startstate']==-7||$v['task_startstate']==-8){
            if ($v['task_status'] == 5 || $v['task_status'] == 6) {
                //进度在0到100之间，或者状态为-6的，表示有任务在执行或等待执行
                array_push($aData, $v['id']);
            }
        }
//         dl("openvas.so");
//    vas_bd_initialize(INTERFACE_ROOT,9390);
//    foreach ($rows as $k => $v1) {
//        //未执行返回-2，已执行返回-1，正在执行返回0-100，暂停返回-3，停止返回-4
//        $uuids = $v1['task_uuid']."|".$v1['web_enable']."|".$v1['id'];
//        $status = vas_bd_gettask($uuids);//var_dump($status);
//        if(($status>=0 && $status<=100)||$status==-6){
//            array_push($aData,$v1['id']);
//        }
//    }
//        foreach ($rows as $k => $v1) {
//        //未执行返回-2，已执行返回-1，正在执行返回0-100，暂停返回-3，停止返回-4 ,-6等待扫描，-7正在停止，-8正在暂停
//        if(($v['task_progress']>=0 && $v['task_progress']<=100)&&($v['task_startstate']==-7||$v['task_startstate']==-8)){
//           //进度在0到100之间，且状态为-7或-8的
//            break;
//        }elseif(($v['task_progress']>=0 && $v['task_progress']<=100)||$v['task_startstate']==-6){
//            //进度在0到100之间，或者状态为-6的，表示有任务在执行或等待执行
//            array_push($aData,$v1['id']);
//        }
//    }
        return count($aData);

    }

    /**/
    function actionViewhostmsg()
    {
        global $db, $act;
        template2($act . '/viewhostmsg', array());
    }


    function test()
    {
        global $db, $act, $show;
        $rows = array();
        $ids = '21,22,23,24,25,28,29,30';
        $uuidrows = $db->fetch_all("SELECT t.task_uuid,t.web_enable FROM task_manage AS t WHERE t.id in (" . $ids . ") ");
        foreach ($uuidrows as $k => $v) {
            $uuidrow[] = $v['task_uuid'];
        }
        array_filter($uuidrow);
        if (!empty($uuidrow)) {
            $uuids = implode(",", $uuidrow);
        }
        $rows[] = $uuids;
        echo json_encode($rows);
        exit;
    }

    function actionGetHostmsg2()
    {
        global $db, $act;
        $aPost = $_POST;
        if ($aPost) {
            if ($aPost['task_id']) {
                $tsql = "SELECT * FROM bd_host_task_manage where id = " . $aPost['task_id'];
                $res = $db->fetch_first($tsql);
                $aData['task_id'] = $res['id'];
                $aData['task_name'] = $res['name'];

                $usql = "SELECT * FROM bd_host_msg_{$aPost['task_id']}";
                //echo $usql;die;
                $ures = $db->fetch_first($usql);
               // var_dump($ures);die;
                $aData['ip'] = $ures['ip'];
                $aData['os'] = $ures['os'];
                $aData['device_type'] = $ures['device_type'];
                $aData['net_distance'] = $ures['net_distance'];
            }
        }
        echo json_encode($aData);
        exit;
    }

    function actionGetHostmsg()
    {
        global $db, $act;
        $aPost = $_POST;
        if ($aPost) {
            if ($aPost['task_id']) {
                $tsql = "SELECT * FROM bd_host_task_manage where id = " . $aPost['task_id'];
                $res = $db->fetch_first($tsql);
                $aData['task_id'] = $res['id'];
                $aData['task_name'] = $res['name'];

                $usql = "SELECT * FROM bd_host_msg_" . $aPost['task_id'] . " WHERE ip ='" . $aPost['ipadd'] . "'";
                $ures = $db->fetch_first($usql);
                $aData['ip'] = $aPost['ipadd'];
                $aData['os'] = $ures['os'];
                $aData['device_type'] = $ures['device_type'];
                $aData['net_distance'] = $ures['net_distance'];
            }
        }
        echo json_encode($aData);
        exit;
    }

    function actionGetHostPort()
    {
        global $db, $act;
        $aPost = $_POST;
        $taskportres = '';
        $page = intval($aPost['page']);
        $perpage = intval($aPost['pagesize']);
        $page = $page > 1 ? $page : 1;
        $total = $db->result_first("select count(*) from bd_host_port_" . $aPost['task_id'] . "  WHERE ip ='" . $aPost['ip'] . "' and port<10000");
        $maxPage = ceil($total / $perpage);
        $page = $page >= $maxPage ? $maxPage : $page;
        $start = ($page - 1) * $perpage;
        if ($aPost['task_id']) {
            $sql = "SELECT * FROM bd_host_port_" . $aPost['task_id'] . " WHERE ip ='" . $aPost['ip'] . "' and port <10000  LIMIT $start,$perpage";
            $taskportres = $db->fetch_all($sql);
        }
        $rows['Rows'] = $taskportres;
        $rows['Total'] = $total;
        echo json_encode($rows);
        exit;
    }

    function actionGetHostPort2()
    {
        global $db, $act;
        $aPost = $_POST;
        $taskportres = '';
        $page = intval($aPost['page']);
        $perpage = intval($aPost['pagesize']);
        $page = $page > 1 ? $page : 1;
        $total = $db->result_first("select count(*) from bd_host_port_" . $aPost['task_id'] . "  WHERE ip ='" . $aPost['ip'] . "' and port>=10000");
        $maxPage = ceil($total / $perpage);
        $page = $page >= $maxPage ? $maxPage : $page;
        $start = ($page - 1) * $perpage < 0 ? 0 : ($page - 1) * $perpage;
        if ($aPost['task_id']) {
            $sql = "SELECT * FROM bd_host_port_" . $aPost['task_id'] . " WHERE ip ='" . $aPost['ip'] . "' and port>=10000 LIMIT " . $start . "," . $perpage;
            $taskportres = $db->fetch_all($sql);
        }
        $rows['Rows2'] = $taskportres;
        $rows['Total2'] = $total;
        echo json_encode($rows);
        exit;
    }

//获取任务最新状态
    function actionGettasknewstatus()
    {
        global $db, $act;
        $aPost = $_POST;
        $taskid = $aPost['taskid'];
        $type = $aPost['type'];
        //var_dump($taskid);
        if ($taskid && $type) {
            if($type=='主机'){
                $sql="select * from bd_host_task_manage WHERE id='$taskid'";
            }elseif ($type=='web'){
                $sql="select * from bd_web_task_manage WHERE id='$taskid'";
            }else{
                $sql="select * from bd_weakpwd_task_manage WHERE id='$taskid'";
            }
            $taskNewStatus=$db->fetch_first($sql);
            $taskNewStatus['task_status']=$taskNewStatus['status'];

            $rows['data'] = $taskNewStatus;
            //var_dump($rows['data']);
            echo json_encode($rows);exit;
        }

    }


    function actionGettaskmsg(){
        $start_time=[];
        global $db;
        $res=$db->fetch_all("select * from task_manage where task_status in (5,6,7,8,9)");

        if($res){
            $use_time=time()-strtotime(min(array_column($res,'start_time')));
            echo json_encode(['success'=>true,'time'=>$use_time,'data'=>$res]);
        }else{
            echo json_encode(['success'=>false]);
        }
    }

    //添加主机任务
    public function actionAddHostTask(){

        global $db, $act, $show;
        $_POST['target_ip']=$this->deal_ip(trim($_POST['target_ip']),$_POST);
        $sPost=$_POST;

        $targrtip = trim($sPost['target_ip']);
        $target_ip= $this->check_ip($targrtip);    //检测ip合法性
        $Transaction = Yii::$app->db->beginTransaction();
        if(Yii::$app->request->get('uuid') !='undefined'){
            $model=new BdHostTaskManage();
            $model = $model::findOne(['uuid'=>Yii::$app->request->get('uuid')]);
        }else{
            $model = new BdHostTaskManage();
            $row =$model::findOne(['name'=>$sPost['task_name']]);
            if($row){
                echo json_encode(['success'=>false,'msg'=>'任务名已存在~~']);die;
            }
        }
        $model->uuid=uuid();
        $model->name=Yii::$app->request->post('task_name','');
        $model->target=$target_ip;
        $model->host_policy=Yii::$app->request->post('host_policy','');
        $model->port_policy=Yii::$app->request->post('port_policy','');
        $model->max_hosts=Yii::$app->request->post('host_thread','');  //最大主机数
        $model->max_checks=Yii::$app->request->post('host_max_script',''); #最大线程数
        $model->timeout=Yii::$app->request->post('host_timeout','');
        $model->smb_enable=Yii::$app->request->post('smb_enable',0);
        $model->smb_user=Yii::$app->request->post('smb_user','');
        $model->smb_passwd=Yii::$app->request->post('smb_passwd','');
        $model->esxi_enable=Yii::$app->request->post('esxi_enable',0);
        $model->esxi_user=Yii::$app->request->post('esxi_user','');
        $model->esxi_passwd=Yii::$app->request->post('esxi_passwd','');
        $model->ssh_enable=Yii::$app->request->post('ssh_enable',0);
        $model->ssh_user=Yii::$app->request->post('ssh_user','');
        $model->ssh_passwd=Yii::$app->request->post('ssh_passwd','');
        $model->ssh_port=Yii::$app->request->post('ssh_port','');
        $model->email=Yii::$app->request->post('email','');
        $model->ftp_enable=Yii::$app->request->post('ftp_enable',0);
        $model->schedule_enable=Yii::$app->request->post('ifSchedule',0);
        $model->schedule_time=Yii::$app->request->post('date','0000-00-00 00:00:00');
        $model->schedule_num=Yii::$app->request->post('num','0');
        $model->schedule_period=Yii::$app->request->post('period','0');
        $model->schedule_period_unit=Yii::$app->request->post('periodunit','');
        $model->timezone='PRC';
        $model->sort=time();
        $model->save();
        try{
            if(Yii::$app->request->get('uuid') !='undefined'){
                $data['msg']='修改任务成功';
            }else{
                $data['msg']='保存任务成功';
            }
            $data['success']=true;
            saveOperationLog(['sAct'=>$act,'username'=>$_SESSION['username']]);
            echo json_encode($data);die;
            $Transaction->commit();
        }catch (Exception $e){
            $Transaction->rollBack();
            print $e->getMessage();
            exit();
        }

    }

    //添加web任务
    public function actionAddWebTask(){
        global $db, $act, $show;
        $sPost=$_POST;
        $target_domain=$this->deal_domain(trim($_POST['target_domain']),$_POST);

        if(!empty($target_domain)){
            $target_domain=str_replace("\r\n",',',$target_domain);
            $target_domain=(trim($target_domain,','));
            $a_domain = explode(",",$target_domain);
            array_filter($a_domain);
            $d_count = count($a_domain);
            if($d_count > 10){
                $data['success'] = false;
                $data['msg'] = '扫描对象：批量域名不能多于10';
                echo json_encode($data);
                exit;
            }
            $s_r = count($a_domain)+1;
            foreach($a_domain as $k=>$v){
                $s_r = $s_r-1;
                if(!checkDomain($v)){  //检测域名合法性
                    $data['success'] = false;
                    $data['msg'] = '扫描对象：批量域名第'.$s_r.'行格式错误';
                    echo json_encode($data);
                    exit;
                }
            }
        }
        if($_POST['web_enable']==1){
            $Transaction = Yii::$app->db->beginTransaction();
            try{

                if(Yii::$app->request->get('uuid') !='undefined'){
                    $model=new BdWebTaskManage();
                    $model = $model::findOne(['uuid'=>Yii::$app->request->get('uuid')]);
                }else{
                    $model = new BdWebTaskManage();
                    $row =$model::findOne(['name'=>$sPost['task_name']]);
                    if($row){
                        echo json_encode(['success'=>false,'msg'=>'任务名已存在~~']);die;
                    }
                }
                $model->uuid=uuid();
                $model->name=Yii::$app->request->post('task_name','');
                $model->target=$target_domain;
                $model->thread=Yii::$app->request->post('web_thread','');
                $model->policy_id=Yii::$app->request->post('web_policy','');
                $model->timeout=Yii::$app->request->post('web_domain_timeout','');
                $model->max_url_count=Yii::$app->request->post('max_url_count',0);
                $model->spider_enable=Yii::$app->request->post('spider_enable',0);
                $model->schedule_enable=Yii::$app->request->post('ifSchedule',0);
                $model->schedule_time=Yii::$app->request->post('date','0000-00-00 00:00:00');
                $model->schedule_num=Yii::$app->request->post('num','0');
                $model->schedule_period=Yii::$app->request->post('period','0');
                $model->schedule_period_unit=Yii::$app->request->post('periodunit','');
                $model->timezone='PRC';
                $model->status=2;
                $model->sort=time();

                $model->login_enable = Yii::$app->request->post('login_enable','0');
                $model->login_type=Yii::$app->request->post('login_type','1');
                $model->login_test_url=Yii::$app->request->post('test_url','');
                if($model->login_type==3){ //代理模式时参数为域名
                    $model->login_params=Yii::$app->request->post('target_domain','');
                }elseif($model->login_type==2){  //账号密码模式，参数为login_url=xxx&xxx
                    $model->login_params=Yii::$app->request->post('params','').'&login_url='.Yii::$app->request->post('login_url','');
                }else{  //cookie模式
                    $model->login_params='';
                }
                $model->cookies=Yii::$app->request->post('cookie','');
                $model->login_flag=Yii::$app->request->post('login_flag','0');
               // var_dump($model->attributes);die;

                $model->save();
                if(Yii::$app->request->get('uuid') !='undefined'){
                    $data['msg']='修改任务成功';
                }else{
                    $data['msg']='新建任务成功';
                }

//                die;
                $data['success']=true;
                saveOperationLog(['sAct'=>$act,'username'=>$_SESSION['username']]);
                echo json_encode($data);die;
                $Transaction->commit();
            }catch (Exception $e){
                $Transaction->rollBack();
                print $e->getMessage();
                exit();
            }
        }
    }

    //添加弱密码任务
    public function actionAddWeakTask(){
        global $db, $act, $show;

        $_POST['target_ip']=$this->deal_ip(trim($_POST['target_ip']),$_POST);
        $_POST['target_domain']=$this->deal_domain(trim($_POST['target_domain']),$_POST);
        $sPost=$_POST;
        $targrtip = trim($sPost['target_ip']);
        $target_ip= $this->check_ip($targrtip);    //检测ip合法性
        if($_POST['weak_enable']==1){
            $Transaction = Yii::$app->db->beginTransaction();
            try{
                if(Yii::$app->request->get('uuid') !='undefined'){
                    $model=new BdWeakpwdTaskManage();
                    $model = $model::findOne(['uuid'=>Yii::$app->request->get('uuid')]);
                }else{
                    $model = new BdWeakpwdTaskManage();
                    $row =$model::findOne(['name'=>$sPost['task_name']]);
                    if($row){
                        echo json_encode(['success'=>false,'msg'=>'任务名已存在~~']);die;
                    }
                }
//                var_dump($sPost);die;
                $model->uuid=uuid();
                $model->name=Yii::$app->request->post('task_name','');
                $model->target=$target_ip;
                $model->thread=Yii::$app->request->post('weak_thread','');
                $model->policy=Yii::$app->request->post('weak_policy','');
                $model->timeout=Yii::$app->request->post('weak_timeout','');
                $model->schedule_enable=Yii::$app->request->post('ifSchedule',0);
                $model->schedule_time=Yii::$app->request->post('date','0000-00-00 00:00:00');
                $model->schedule_num=Yii::$app->request->post('num','0');
                $model->schedule_period=Yii::$app->request->post('period','0');
                $model->schedule_period_unit=Yii::$app->request->post('periodunit','');
                $model->timezone='PRC';
                $model->status=2;
                $model->sort=time();
                $model->save();
                if(Yii::$app->request->get('uuid') !='undefined'){
                    $data['msg']='修改弱密码任务成功';
                }else{
                    $data['msg']='新建弱密码任务成功';
                }
                $data['success']=true;
                saveOperationLog(['sAct'=>$act,'username'=>$_SESSION['username']]);
                echo json_encode($data);die;
                $Transaction->commit();
            }catch (Exception $e){
                $Transaction->rollBack();
                print $e->getMessage();
                exit();
            }
        }
    }

    //执行任务
    public function actionWorktask(){
        $ids=explode(',',$_POST['ids']);
        $model=new TaskManage();
        foreach ($ids as $v){
            $vv=explode(':',$v);

            if($vv[1]=='弱密码'){
                $model->task_uuid= $vv[0];
                $model->action =4;
                $model->type=3;
                $model->save();
                Yii::$app->db->createCommand("update bd_weakpwd_task_manage set status=6, start_time=".time()." WHERE uuid='$vv[0]' ")->execute();
            }elseif($vv[1]=='web'){
                Yii::$app->db->createCommand("delete from task_manage where task_uuid='$vv[0]' and type=2")->execute();
                Yii::$app->db->createCommand("insert into task_manage set action=4 , task_uuid='$vv[0]' , type=2")->execute();
                Yii::$app->db->createCommand("update bd_web_task_manage set status=6, start_time=".time()." WHERE uuid='$vv[0]' ")->execute();

                // $sql="insert into task_manage set action=1 , task_uuid='$vv[0]' , type=3";
            }elseif($vv[1]=='主机'){
                Yii::$app->db->createCommand("delete from task_manage where task_uuid='$vv[0]' and type=1")->execute();
                Yii::$app->db->createCommand("insert into task_manage set action=4 , task_uuid='$vv[0]' , type=1")->execute();
                Yii::$app->db->createCommand("update bd_host_task_manage set status=6, start_time=".time()." WHERE uuid='$vv[0]' ")->execute();
                //$sql="insert into task_manage set action=1 , task_uuid='$vv[0]' , type=3";
            }

            echo json_encode(['success'=>true]);
        }
    }

    //停止任务
    public function actionStoptask(){
        $ids=explode(',',$_POST['ids']);

        foreach ($ids as $v){
            $vv=explode(':',$v);
            if($vv[1]=='弱密码'){
                Yii::$app->db->createCommand("insert into task_manage set action=6 ,task_uuid='$vv[0]',type=3")->execute();
                Yii::$app->db->createCommand("update bd_weakpwd_task_manage set status=7 WHERE uuid='$vv[0]'")->execute();
            }elseif($vv[1]=='web'){
                Yii::$app->db->createCommand("insert into task_manage set action=6 ,task_uuid='$vv[0]',type=2")->execute();
                Yii::$app->db->createCommand("update bd_web_task_manage set status=7 WHERE uuid='$vv[0]'" )->execute();
            }else{
                Yii::$app->db->createCommand("insert into task_manage set action=6 ,task_uuid='$vv[0]',type=1")->execute();
                Yii::$app->db->createCommand("update bd_host_task_manage set status=7 WHERE uuid='$vv[0]'")->execute();
            }
        }
        echo json_encode(['success'=>true]);
    }

    //暂停
    public function actionPausetask(){
        $ids=explode(',',$_POST['ids']);

        foreach ($ids as $v){
            $vv=explode(':',$v);
//            if($vv[1]=='弱密码'){
//                Yii::$app->db->createCommand("insert into task_manage set action=5 ,task_uuid='$vv[0]',type=3")->execute();
//                Yii::$app->db->createCommand("update bd_weakpwd_task_manage set status=8 WHERE uuid='$vv[0]'")->execute();
//            }elseif($vv[1]=='web'){
//                Yii::$app->db->createCommand("insert into task_manage set action=5 ,task_uuid='$vv[0]',type=2")->execute();
//                Yii::$app->db->createCommand("update bd_web_task_manage set status=8 WHERE uuid='$vv[0]'" )->execute();
//            }else{
//                Yii::$app->db->createCommand("insert into task_manage set action=5 ,task_uuid='$vv[0]',type=1")->execute();
//                Yii::$app->db->createCommand("update bd_host_task_manage set status=8 WHERE uuid='$vv[0]'")->execute();
//            }
            if($vv[1]=='弱密码'){
                Yii::$app->db->createCommand("insert into task_manage set action=6 ,task_uuid='$vv[0]',type=3")->execute();
                Yii::$app->db->createCommand("update bd_weakpwd_task_manage set status=7 WHERE uuid='$vv[0]'")->execute();
            }elseif($vv[1]=='web'){
                Yii::$app->db->createCommand("insert into task_manage set action=6 ,task_uuid='$vv[0]',type=2")->execute();
                Yii::$app->db->createCommand("update bd_web_task_manage set status=7 WHERE uuid='$vv[0]'" )->execute();
            }else{
                Yii::$app->db->createCommand("insert into task_manage set action=6 ,task_uuid='$vv[0]',type=1")->execute();
                Yii::$app->db->createCommand("update bd_host_task_manage set status=7 WHERE uuid='$vv[0]'")->execute();
            }
        }
        echo json_encode(['success'=>true]);
    }

    function actionEdit(){
        global $db;
        $type=Yii::$app->request->get('type');
        $uuid=Yii::$app->request->get('uuid');
        $periodunit = array('hour'=>'小时','day'=>'天','week'=>'周','month'=>'月');
        $starttime=date('Y-m-d H:i:s',time());

        if($_GET['type']=='weakpwd'){
            if( !empty($uuid)){ //修改获取数据
                $res=Yii::$app->db->createCommand("select * from bd_weakpwd_task_manage WHERE uuid='$uuid'")->queryOne();
                $res['target']=str_replace(',',"\r\n",$res['target']);
                $res['type']=$type;
            }
           // var_dump($res);die;
            //弱密码策略
            $weaks = $db->fetch_all("SELECT * FROM bd_weakpwd_policy ORDER BY id DESC ");
            template2("taskmanage/edit_weak",['data'=>$res,'weaks'=>$weaks,'periodunit'=>$periodunit,'starttime'=>$starttime]);
        }
        elseif($_GET['type']=='host'){
            if(!empty($uuid)){ //修改获取数据
                $res=Yii::$app->db->createCommand("select * from bd_host_task_manage WHERE uuid='$uuid'")->queryOne();
                $res['target']=str_replace(',',"\r\n",$res['target']);
                $res['type']=$type;
            }
            //主机策略
            $host_policy = $db->fetch_all("SELECT * FROM bd_host_policy ORDER BY id  ");
            //扫描端口策略
            $port_policy= $db->fetch_all("SELECT * FROM bd_port_policy ORDER BY id  ");
            template2("taskmanage/edit_host",[
                'data'=>$res,
                'host_policy'=>$host_policy,
                'port_policy'=>$port_policy,
                'periodunit'=>$periodunit,
                'starttime'=>$starttime
            ]);
        }elseif($_GET['type']=='web'){
            //web策略
            $policy = $db->fetch_all("SELECT * FROM bd_web_policy ORDER BY id DESC ");

            if(!empty($uuid)){//修改获取数据
                $res=Yii::$app->db->createCommand("select * from bd_web_task_manage WHERE uuid='$uuid'")->queryOne();
                $res['target']=str_replace(',',"\r\n",$res['target']);
                $res['type']=$type;
            }
            template2("taskmanage/edit_web",['data'=>$res,'policy'=>$policy,'periodunit'=>$periodunit,'starttime'=>$starttime]);
        }
    }

    public function  check_ip($targrtip){
        $i_count=0;
        if (!empty($targrtip)) {
            $target_ip = nl2br($targrtip);  //将分行符"\r\n"转义成HTML的换行符"<br />"
            $target_ip = str_replace("<br />", ",", $target_ip);
            $target_ip = str_replace("\r\n", "", $target_ip);
            $a_ip = explode(",", $target_ip);
//            var_dump($a_ip);die;
            array_filter($a_ip);
            $s_r = count($a_ip) + 1;
            $loginuser=Yii::$app->db->createCommand("select * from bd_sys_scanset")->queryOne();
            //var_dump($loginuser);die;
            foreach ($a_ip as $k => $v) {
                //$s_r = $k+1;
                $s_r = $s_r - 1;
                //把2001::1:200:7-20 处理为 2001::1:200:7-2001::1:200:20
                if (!$this->filter_ip($v)) {
                    $data['success'] = false;
                    $data['msg'] = '扫描对象：批量IP第' . $s_r . '行格式错误';
                    echo json_encode($data);
                    exit;
                } else {
                    $a_target_single = explode("-", trim($v));
                    if (count($a_target_single) == 2) { //ip段
                        $sin0 = $a_target_single[0];
                        $sin1 = $a_target_single[1];
                        //ipv6
                        if (strpos($sin0, ':')) {

                            if (!empty($loginuser['allowIPs'])) {
                                if (!$this->in_allowipv6(explode(',', $loginuser['allowIPs']), $v, 2)) {
                                    $data['success'] = false;
                                    $data['msg'] = '第' . $s_r . '行不在允许扫描的IP范围内';
                                    echo json_encode($data);
                                    exit;
                                }
                            }
                            $ipv6first = intval(substr($sin0, strrpos($sin0, ':') + 1), 16);
                            $ipv6last = intval(substr($sin1, strrpos($sin1, ':') + 1), 16);
                            $ipv6count = intval($ipv6last - $ipv6first) + 1;
                            $i_count = $i_count + $ipv6count;
                        } else {
                            $a_sin0 = explode(".", $sin0);
                            $a_sin1 = explode(".", $sin1);
                            if ($a_sin0[0] == $a_sin1[0] && $a_sin0[1] == $a_sin1[1] && $a_sin0[2] == $a_sin1[2]) {
                                $rootip = INTERFACE_ROOT;
                                $a_rootip = explode(".", $rootip);
                                if ($a_sin0[0] == $a_rootip[0] && $a_sin0[1] == $a_rootip[1] && $a_sin0[2] == $a_rootip[2]) {
                                    if (intval($a_rootip[3]) >= intval($a_sin0[3]) && intval($a_rootip[3]) <= intval($a_sin1[3])) {
                                        $data['success'] = false;
                                        $data['msg'] = '扫描对象：批量IP第' . $s_r . '行网段包含了本机IP';
                                        echo json_encode($data);exit;
                                    }
                                }
                                if (!empty($loginuser['allowIPs'])) {
                                    if (!$this->in_allowip(explode(',', $loginuser['allowIPs']), $v, 2)) {
                                        $data['success'] = false;
                                        $data['msg'] = '扫描对象：批量IP第' . $s_r . '行不在允许扫描的IP范围内';
                                        echo json_encode($data);exit;
                                    }
                                }
                                $i_thiscount = intval($a_sin1[3]) - intval($a_sin0[3]) + 1;
                                $i_count = $i_count + $i_thiscount;
                            } else {
                                $data['success'] = false;
                                $data['msg'] = '扫描对象：批量IP第' . $s_r . '行格式错误，不能跨网段扫描';
                                echo json_encode($data);
                                exit;
                            }
                        }
                    } else {  //ip
                        if (!empty($loginuser['allowIPs'])) {
                            if (!strpos($v, ':') && !$this->in_allowip(explode(',', $loginuser['allowIPs']), $v, 1)) {
                                $data['success'] = false;
                                $data['msg'] = '扫描对象：批量IPV4第' . $s_r . '行不在允许扫描的IP范围内';
                                echo json_encode($data);
                                exit;
                            } else if (strpos($v, ':') && !$this->in_allowipv6(explode(',', $loginuser['allowIPs']), $v, 1)) {
                                $data['success'] = false;
                                $data['msg'] = '扫描对象：批量IPV6第' . $s_r . '行不在允许扫描的IP范围内';
                                echo json_encode($data);
                                exit;
                            }
                        }
                        $i_count = $i_count + 1;
                    }
                }
            }
        }else{
            $data['success'] = false;
            $data['msg'] = '扫描对象不能为空';
            echo json_encode($data);
            exit;
        }
        return $target_ip;
    }

    /**
     *  检测域名
     */
    function checkDomain($domain){
        if(preg_match('/^(http:\/\/|https:\/\/)+([0-9a-zA-Z\.\-\_]{1,32})+(\.[a-zA-Z]{2,5})$/', $domain) || preg_match('/^(http:\/\/|https:\/\/)+((?:(?:25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))\.){3}(?:25[0-5]|2[0-4]\d|((1\d{2})|([1 -9]?\d))))$/', $domain) || preg_match('/^(http:\/\/|https:\/\/)+([0-9a-zA-Z\.\-\_]{1,32})+(\.[a-zA-Z]{2,5}):\d{0,5}$/', $domain) || preg_match('/^(http:\/\/|https:\/\/)+((?:(?:25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))\.){3}(?:25[0-5]|2[0-4]\d|((1\d{2})|([1 -9]?\d)))):\d{0,5}$/', $domain))
        {
            return true;
        }else{
            return false;
        }
    }

    /**
     * 历史任务漏洞风险图
     *
     */
    function actionHistory()
    {
        global $db;
        $uuid = $_REQUEST['uuid'];
        $c_data=[];
        if($_GET['type']=='weak' ){
            $type='弱密码';
            if($_GET['s']=='img'){
                $sql_f = "select end_time,uuid,total,h as H,m as M,l as L,i as I,ip,vul_id,comment from `bd_weakpwd_history`  WHERE uuid='$uuid' ORDER BY end_time";
                $vuls=$db->fetch_all("select vul_id from bd_weakpwd_history  WHERE uuid='$uuid'   ORDER by end_time ");
                $max=$db->fetch_first("select vul_id from bd_weakpwd_history WHERE uuid='$uuid' ORDER by total desc limit 1");
                  // var_dump($vuls);die;
                $vul_ids='';
                foreach ($vuls as $k=>$v){
                    $vul_ids.=$v['vul_id'].',';
                    $newvuls[$k]=explode('|',$v['vul_id']);
                }
                //var_dump($newvuls);die;
                $vul_ids=str_replace('|',',',trim($vul_ids,','));
                $vul_ids=array_unique(explode(',',$vul_ids));
                //var_dump(count($vul_ids));die;
                sort($vul_ids);
            //    var_dump($vul_ids);die;
                $newexist=[];
                foreach ($newvuls as $k=>$v){
                    foreach ($vul_ids as $k1=>$v1){
                        if(in_array($v1,$v)){
                            $exist='Y';
                        }else{
                            $exist='N';
                        }
                        $newexist[]=$exist;
                        $arr[$k1]['vul_name']=$v1;

                    }
                }
                $newexists=array_chunk($newexist,count($vul_ids));
                //var_dump($newexists);die;
                foreach ($newexists as $k=>$v){
//            var_dump($v);
                    foreach ($v as $k1=>$v1){
                        $arr[$k1][($k+1).'times']=$v1;
                    }
                }

                $newarr['Rows']=$arr;
              //  $newarr['total']=count($vul_ids);
                echo json_encode($newarr);die;
            }else{
                $sql_f = "select max(end_time) as end_time,uuid,total,h as H,m as M,l as L,i as I,ip,vul_id,comment from `bd_weakpwd_history`  WHERE uuid='$uuid' group by ip ORDER BY end_time";
              //  echo $sql_f;die;
               $arr_f = $db->fetch_all($sql_f);
              //  var_dump($arr_f);die;
                if (!empty($arr_f)) {

                    //var_dump($arr_f);
                    $arr_d = array();
                    $vul='';

                    foreach ($arr_f as $k => $val) {
                        $val['h_vuls']=$val['m_vuls']=$val['l_vuls']=$val['i_vuls']='';
                        $val['R'] = $val['H'] > 0 ? 'h' : ($val['M'] > 0 ? 'm' : ($val['L'] > 0 ? 'l' : 'i'));//增加风险评估列的数据
                        $val['time'] = date('Y-m-d H:i:s',$val['end_time']);
                        $val['total'] = $val['H'] + $val['M'] + $val['L'] + $val['I'];

                        $vuls_arr=explode(',',$val['vul_id']);
                        // var_dump($vuls_arr);die;
                        //var_dump(explode('|',$vuls_arr[0]));die;
                        foreach (explode('|',$vuls_arr[0]) as $i=> $r){
                            if(!empty($vuls[$r])){
                                $val['h_vuls'] .= $vuls[$r]."<br>";
                            }
                        }
                        foreach (explode('|',$vuls_arr[1]) as $i=> $r){
                            if(!empty($vuls[$r])){
                                $val['m_vuls'] .= $vuls[$r]."<br>";
                            }
                        }
                        foreach (explode('|',$vuls_arr[2]) as $i=> $r){
                            if(!empty($vuls[$r])){
                                $val['l_vuls'] .= $vuls[$r]."<br>";
                            }
                        }
                        foreach (explode('|',$vuls_arr[3]) as $i=> $r){
                            if(!empty($vuls[$r])){
                                $val['i_vuls'] .= $vuls[$r]."<br>";
                            }
                        }
                        $val['type']=$type;
                        //var_dump($val['vul']);die;
                        $val = array_reverse($val);//翻转数组
                        $arr_t[$k] = $val;
                        $f_val = array_values($val);//返回值组成的新数组
                        $arr_f[$k] = $f_val;
                    }
                    $aJson['Rows']=$arr_t;
                    // var_dump($arr_t);die;
                    $aJson['alldata'] = $arr_t;
//            var_dump($c_data);die;
                    $aJson['c_data'] = array_values($c_data);
                    //  var_dump($arr_f);die;
                    array_push($arr_d, $arr_f);
                    $ttt = array_column($arr_t, 'R');//返回数组某一列的值
                    $ddd = array_column($arr_t, 'time');
                    $H = array_column($arr_t, 'H');
                    $M = array_column($arr_t, 'M');
                    $L = array_column($arr_t, 'L');
                    $I = array_column($arr_t, 'I');
                    $ip = array_column($arr_t, 'ip');
                    array_push($arr_d, $ttt);
                    array_push($arr_d, $ddd);
                    array_push($arr_d, $H);
                    array_push($arr_d, $M);
                    array_push($arr_d, $L);
                    array_push($arr_d, $I);
                    array_push($arr_d, $ip);
                    //var_dump($arr_d);exit;
                    $aJson['success'] = true;
                    $aJson['mdata'] = $arr_d;


                } else {
//            $aJson['success'] = false;
//            $aJson['mdata'] = '没有相关风险结果';
                }
                echo json_encode($aJson);
                exit;

            }
        }elseif($_POST['type']=='主机'){
            if($_GET['s']=='img'){    //点击查看显示图表
                $vuls= ArrayHelper::map($db->fetch_all("select vul_id,vul_name from bd_host_vul_lib"),'vul_id','vul_name'); //所有的漏洞
                $sql_f = "select end_time,uuid,total,h as H,m as M,l as L,i as I,ip,vul_id from `bd_host_history`  WHERE uuid='$uuid' ORDER BY end_time";
                $sql_v = "select max(total) total,vul_id from bd_host_history WHERE uuid='$uuid'" ;
                $arr_v = $db->fetch_first($sql_v);
                $arr_v['vul_id']=str_replace('H:','',$arr_v['vul_id']);
                $arr_v['vul_id']=str_replace('M:','',$arr_v['vul_id']);
                $arr_v['vul_id']=str_replace('L:','',$arr_v['vul_id']);
                $arr_v['vul_id']=str_replace('I:','',$arr_v['vul_id']);
                $arr_v['vul_id']=str_replace('|',',',$arr_v['vul_id']);
                $sql_g="select count(1) as num from bd_host_history WHERE uuid = '$uuid' ";
                $num= ($db->result_first($sql_g));
             // var_dump($num);die;
                //$times = array_column($dataBytime,'num');
                //var_dump($times);die;
                // $vuls_names=[];


                foreach (explode(',',$arr_v['vul_id']) as $k=>$v){
                    if(!empty($vuls[$v])){
                        $c_data[$k]['vul_name']=$vuls[$v];
                      //  $db->fetch_all("select vul_id from bd_host_history WHERE ")
                        $ifexist = 'Y';
                        for($i=1;$i<=$num;$i++){
                            $c_data[$k]['第'.$i.'次'] = $ifexist;
                        }
                        $c_data[$k]['total'] = $num; //总次数

                    }
                };



               // var_dump($c_data);die;
            }else{
                $type='主机';
                $sql_f = "select max(end_time) as end_time,uuid,total,h as H,m as M,l as L,i as I,ip,vul_id from `bd_host_history`  WHERE uuid='$uuid' group by ip ORDER BY end_time";
            }

        }elseif($_POST['type']=='web'){
            $type='web';
            if($_GET['s']=='img'){
                $sql_f = "select end_time,uuid,total,h as H,m as M,l as L,i as I,domain as ip,vul_id from `bd_web_history`  WHERE uuid='$uuid' ORDER BY end_time";
            }else{
                $sql_f = "select max(end_time) as end_time,uuid,total,h as H,m as M,l as L,i as I,domain as ip,vul_id from `bd_web_history`  WHERE uuid='$uuid' group by ip ORDER BY end_time";
            }
            $sql="select  vul_id,vul_name from bd_web_vul_lib";
        }

    }

    //渲染模板
    public function actionHistoryRiskView(){
        global $act;
        $lv  = intval($_GET['lv']);//lv用于判断画哪种图或表
        $zct = filterStr($_GET['zct']);//zct用于作图表的标题和作为查看时的传参
        $index = intval($_GET['index']);//键
        template2('/taskmanage/history_risk', array('lv'=>$lv,'zct'=>1,'index'=>$index,'uuid'=>$_GET['uuid']));

    }

    //获取单个任务的历史风险
    public function actionShowlogs(){
        global $db;
        $sPost = $_POST;
        $aJson = array();
        $pid = intval($sPost['part_id']);

        //$sql_f = "select ip,report_time,num,count(risk_factor='I' or null) as I,count(risk_factor='L' or null) as L,count(risk_factor='M' or null) as M,count(risk_factor='H' or null) as H from bd_host_result_sum_".$tid." where ip="."'".$zcip."'"." group by num order by num asc";
        $sql_f = "select report_time,num,h as H,m as M,l as L,i as I from `bd_weakpwd_history` WHERE part_id=".$pid;
        $arr_f = $db->fetch_all($sql_f);
        //var_dump($arr_f);exit;
        $arr_d = array();
        foreach ($arr_f as $k=>$val){
            $val['R'] = $val['H']>0? '4':($val['M']>0? '3':($val['L']>0? '2':'1'));//增加风险评估列的数据
            $val['time'] = $val['report_time'];
            $val = array_reverse($val);
            $arr_t[$k] = $val;
            $f_val = array_values($val);
            $arr_f[$k] = $f_val;
        }
        array_push($arr_d,$arr_f);
        $ttt = array_column($arr_t,'R');
        $ddd = array_column($arr_t,'report_time');
        array_push($arr_d,$ttt);
        array_push($arr_d,$ddd);
        //var_dump($arr_d);exit;
        $aJson['success'] = true;
        $aJson['data'] = $arr_d;
        echo json_encode($aJson);
        exit;
    }


    public function actionLogintest(){
        $login_type=Yii::$app->request->post('login_type'); //模式
        $test_url=Yii::$app->request->post('test_url');  //测试url
       // $login_url=Yii::$app->request->post('login_url'); //登录url

        if($login_type == 1){ //1：cookie模式
            $params=Yii::$app->request->post('cookie'); //参数
            //echo "python /home/bluedon/bdscan/bdwebscan/bdwebpy/login_test.py $login_type $test_url $params";die;
            exec("python /home/bluedon/bdscan/bdwebscan/bdwebpy/login_test.py $login_type $test_url $params", $res);

        }elseif($login_type == 2){ //1：账号密码模式
            $params=Yii::$app->request->post('params'); //参数
            exec("python /home/bluedon/bdscan/bdwebscan/bdwebpy/login_test.py $login_type $test_url $params", $res);
        }
       // var_dump($res);die;
        if($res){
            $res= json_decode($res[0],true);
            if($res['status']==1){

                echo json_encode(['state'=>1, 'msg'=>'登录成功!']);
            }else{
                echo json_encode(['state'=>0,'msg'=>'登录失败']);
            }
        }else{
            echo json_encode(['state'=>0,'msg'=>'登录异常']);die;
        }
    }

    public function actionMail(){
        $mail= Yii::$app->mailer->compose();
        $mail->setTo('1002310963@qq.com');
        $mail->setSubject("邮件测试");
//$mail->setTextBody('zheshisha ');   //发布纯文字文本
        $mail->setHtmlBody("<br>问我我我我我");    //发布可以带html标签的文本
        if($mail->send())
            echo "success";
        else
            echo "failse";
    }

    public function actionHistoryVul(){
        $data=$_GET['data'];
        template2('/taskmange/history_vul',['data'=>$data]);
    }

    public function actionHelp(){
        template2('/taskmanage/help');
    }
}
?>

