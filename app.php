<?php
/**
 * Created by PhpStorm.
 * User: Administrator
 * Date: 2017/4/15
 * Time: 11:44
 */
$fh=fopen(Yii::$app->basePath.'/messages/en_US/en1.csv',"r");
$arr=[];
while ($line=fgetcsv($fh,1000,",")){
//var_dump($line);

    $Name=iconv('gbk','utf-8',$line[0]);
    // var_dump($Name);
    //echo $Name;
    $arr[$Name] = $line[1];
}
//return $arr;
return [
    '系统监控台'=>'Home',
    '检测平台'=>'Check',
    '任务管理'=>'Scans',
    '主机扫描'=>'Host',
    'web扫描'=>'Web',
    '弱密码扫描'=>'Weak Password',
    '资产管理'=>'Assets',
    '网络拓扑'=>'Topology',
    '策略管理'=>'Policies',
    '主机扫描策略'=>'Host',
    '端口扫描策略'=>'Port',
    'Web扫描策略'=>'Web',
    '弱密码扫描策略'=>'Weak Password',
    '弱密码参数'=>'Weak Param',
    '报告管理'=>'Reports',
    '主机报告'=>'Host',
    'web报告'=>'Web',
    '弱密码报告'=>'Weak Password',
    '检测工具'=>'Network Tool',
    '用户管理'=>'Accounts',
    '用户列表'=>'User List',
    '系统管理'=>'System',
    '系统维护'=>'System maintenance',
    '系统设置'=>'System setting',
    '网络配置'=>'Network config',
    '服务设置'=>'Service setting',
    '日志审计'=>'Logs',
    '日志查询'=>'Query',
    '日志下载'=>'Download',
    '添加'=>'Add',
    '编辑'=>'Edit',
    '删除'=>'Delete',
    '执行'=>'Execute',
    '停止'=>'Stop',
    '暂停'=>'Pause',
    '查询'=>'Search',
    '精确查询'=>'Exact Search',
    '是否要删除部门？'=>'Do you want to delete the Department?',
    '同时删除资产'=>'Delete assets at the same time',
    '任务名称'=>'Task Name',
    '任务类型'=>'Task Type',
    '状态'=>'Status',
    '调度类型'=>'Scheduling Type',
    '开始时间'=>'Start Time',
    '结束时间'=>'End Time',
    '操作'=>'Operation',
    '基础配置'=>'Basic Configuration',
    '主机扫描高级配置'=>'Advanced configuration',
    '任务基本信息'=>'Task basic information',
    '批量IP'=>'Batch IP',
    '格式'=>'Format',
    '或'=>'or',
    '请输入IP'=>'Please enter IP',
    '以回车（换行）分隔'=>'Press Enter to Separate',
    '扫描方式'=>'Scanning mode',
    '快速扫描'=>'Fast scan',
    '完全扫描'=>'Full scan',
    '端口策略'=>'Scan port',
    '主机策略'=>'Host policy',
    '重置'=>'reset',
    '并发主机数'=>'Concurrent hosts number',
    '主机线程数'=>'Host thread number',
    '主机扫描超时'=>'Host scan timeout',
    '是否开启SSH'=>'SSH certificate',
    'SSH 用户名'=>'SSH username',
    'SSH 密码'=>'SSH password',
    'SSH 端口'=>'SSH port',
    '是否开启SMB'=>'SMB certificate',
    'SMB 用户名'=>'SMB username',
    'SMB 密码'=>'SMB password',
    '自动发送报告到指定邮箱'=>'Automatically send report to mail',
    '邮箱地址'=>'mail address',
    '自动发送报告到指定ftp服务器'=>'Automatically send report to ftp serve',
    '（单位：分钟）'=>'(unit: minutes)',
    'web扫描高级配置'=>'Advanced configuration',
    '批量域名'=>'Batch domain',
    'WEB策略'=>'Web policy',
    '开启'=>'Open',
    '开启爬虫'=>'Crawler',
    '扫描线程'=>'Thread number',
    '扫描超时'=>'Scan timeout',
    '是否定时执行任务'=>'Whether to perform tasks on time',
    '是否开启登录扫'=>'Whether to open login scan',
    '端口'=>'Port',
    '请输入域名'=>'Please enter Domain',
    '端口为可选项'=>'the port is optional',
    '该项必须填写！'=>'This item must be filled out',
    '弱密码策略'=>'Weak password policy',
    '弱密码扫描高级配置'=>'Advanced configuration',
    '高级设置'=>'Advanced setting',
    '（单位：秒）'=>'(unit: seconds)',
    ' 警告: 包含远程协助的策略可能会导致单用户登录的系统退出当前账号'=>'Warning:   Policies that include remote assistance can cause a single user logged system to exit the current account',
    '资产树'=>'Asset tree',
    '上次登录时间'=>'Last logon time',
    '增加部门'=>'Add department',
    '增加资产'=>'Add assets',
    '风险趋势图'=>'Risk trend map',
    '删除资产'=>'Delete assets',
    '添加到任务扫描'=>'Added to task scanning',
    '导入'=>'Import',
    '导出'=>'Export',
    '资产名称'=>'Asset name',
    '资产所属部门'=>'Department',
    '负责人'=>'Master',
    'IPV4地址'=>'IPV4',
    '资产状态'=>'Status',
    '操作系统'=>'OS',
    '新增部门'=>'Add department',
    '联系方式'=>'Contact information',
    '工作邮件'=>'Work mail',
    '备注'=>'Remark',
    '提交'=>'Submit',
    '取消'=>'Cancel',
    '消息'=>'Message',
    '请先选择部门！'=>'Please select the Department first!',
    '请选择部门'=>'Please select the Department',
    '确定'=>'Confirm',
    '部门信息'=>'Department information',
    '新增资产'=>'Add assets',
    '资产标识'=>'Name',
    '所属部门'=>'Department',
    '资产类型'=>'Type',
    '资产价值'=>'Value',
    'MAC地址'=>'Mac address',
    '设备名称'=>'Device name',
    '跳跃点'=>'Jumping point',
    '端口号'=>'Port',
    '状态'=>'Status',
    '服务类型'=>'Service type',
    '版本号'=>'Ver',
    '请选择资产'=>'Please select assets',
    '导入资产'=>'Import assets',
    '下载模板'=>'Download templates',
    '编辑资产信息'=>'Edit assets',
    '查看资产信息'=>'View asset information',
    '自发现配置'=>'Automatic discovery config',
    '部门名称'=>'Department',
    'ip范围'=>'IP range',
    '添加扫描任务'=>'Add scan task',
    '添加到任务列表'=>'Add to task list',
    '显示类型'=>'Display type',
    '网络搜索'=>'Web search',
    '现有资产'=>'Existing assets',
    '目标'=>'Target',
    '开始'=>'Start',
    '配置'=>'Config',
    '部门'=>'Department',
    '部门可多选'=>'Multiselect',
    '安全'=>'Safe',
    '低风险'=>'Low',
    '中风险'=>'Medium',
    '高风险'=>'High',
    '在线'=>'On-line',
    '在线_未知'=>'On-line_Unknown',
    '在线_安全'=>'On-line_safe',
    '在线_低风险'=>'On-line_low',
    '在线_高风险'=>'On-line_high',
    '在线_中风险'=>'On-line_medium',
    '离线'=>'Off-line',
    '离线_安全'=>'Off-line_Safe',
    '离线_低'=>'Off-line_Low',
    '离线_低风险'=>'Off-line_Low',
    '离线_中'=>'Off-line_Medium',
    '离线_中风险'=>'Off-line_Medium',
    '离线_高'=>'Off-line_High',
    '离线_高风险'=>'Off-line_High',
    '离线_未知'=>'Off-line_Unknown',
    '未知'=>'Unknown',
    '路由器_安全'=>'Route_Safe',
    '路由器_低'=>'Route_Low',
    '路由器_低风险'=>'Route_Low',
    '路由器_中'=>'Route_Medium',
    '路由器_中风险'=>'Route_Medium',
    '路由器_高'=>'Route_High',
    '路由器_高风险'=>'Route_High',
    '路由器_未知'=>'Route_Unknown',
    '交换机_安全'=>'Switch_Safe',
    '交换机_低'=>'Switch_Low',
    '交换机_低风险'=>'Switch_Low',
    '交换机_中'=>'Switch_Medium',
    '交换机_中风险'=>'Switch_Medium',
    '交换机_高'=>'Switch_High',
    '交换机_高风险'=>'Switch_High',
    '交换机_未知'=>'Switch_Unknown',
    '自己'=>'Self',
    '点击展现该网段的所有ip节点'=>'Click on all IP nodes that display this segment',
    '网段'=>'Segment',
    '上午'=>'a.m. ',
    '下午'=>'p.m. ',
    '扫描目标'=>'Scan target',
    '扫描时间'=>'Scan time',
    '拓扑图配置'=>'Topology configuration',
    '限制所有网段显示总数'=>'Limit total nodes',
    '限制网段显示的叶子数'=>'Limit nodes of segment',
    '当输入框为空时，用默认配置值'=>'When the input box is empty, use the default configuration value',
    '还原'=>'Restore',
    '保存为图片'=>'Save as picture',
    '策略名称'=>'Policy Name',
    '新增主机扫描策略'=>'Add Host Scan Policy',
    '高'=>'High',
    '中'=>'Medium',
    '低'=>'Low',
    '信息'=>'Information',
    '全选'=>'Select all',
    '反选'=>'Invert selection',
    '漏洞名称'=>'Vulnerability name',
    '风险等级'=>'Risk level',
    '分类'=>'Classification',
    '发现时间'=>'Discovery time',
    '漏洞分类'=>'Types',
    'CVE年份'=>'CVE year',
    '新增扫描端口策略'=>'Add Port Scan Policy',
    '其中'=>'And ',
    '指'=>' refer to ',
    '新增WEB应用扫描策略'=>'Add Web Scan Policy',
    '编辑WEB应用扫描策略信息'=>'Edit WEB application scanning policy information',
    '查看WEB应用扫描策略信息'=>'View WEB application scanning policy information',
    '新增弱密码策略'=>'Add Weak Password Policy',
    '选择漏洞'=>'Select vulnerability',
    '选择字典'=>'Select dictionary',
    '弱密码字典'=>' Weak Password Dictionary',
    '字典内容'=>'Dictionary Content',
    '字典格式'=>'Dictionary Format',
    '用户名'=>'Username',
    '密码'=>'Password',
    '每行一条记录，用户名及密码均不允许出现'=>'each line of record, user name and password are not allowed to appear',
    '号'=>'',
    '。'=>'.',
    '：'=>':',
    '导入字典'=>'Import Dictionary',
    '新建文件'=>'NewFile',
    '字典文件需为UTF-8编码格式'=>'Dictionary files need to be encoded in UTF-8 format',
    '浏览'=>'Browse',
    '保存'=>'Save',
    '恢复默认字典'=>'Restore default dictionary',
    '恢复默认字典？'=>'Restore default dictionary?',
    '刷新'=>'Refresh',
    '选择任务'=>'Select task',
    '按住'=>'Hold down ',
    '键可多选'=>' can select multiple',
    '报表类型'=>'Report Type',
    '报告名称'=>'Report Name',
    '报表下载'=>'Report Download',
    '只支持数字、中英文和下划线'=>'Only numbers, Chinese and English are underlined',
    '命令'=>'Command',
    '参数'=>'Parameter',
    '清屏'=>'Clear',
    '请严格按照以下实例填写指令参数'=>'Please fill out the instruction parameters in strict accordance with the following examples',
    '不用填写任何内容'=>'No need to fill in anything',
    '角色'=>'Role',
    '新增用户'=>'Add User',
    '用户名称'=>'Username',
    '用户状态'=>'Status',
    '请选择某一行数据'=>'Please select a row of data',
    '编辑用户信息'=>'Edit user information',
    '查看用户信息'=>'View user information',
    '关闭'=>'Close',
    '重置密码'=>'Reset password',
    '注'=>'Be careful',
    '复杂度：字母数字和特殊字符组合'=>'Complexity: alphanumeric and special character combinations',
    '复杂度：字母和数字组合'=>'Complexity: combination of letters and numbers',
    '设备信息'=>'Device information',
    '产品名称'=>'Product name',
    '产品型号'=>'Product model',
    '软件版本'=>'Software version',
    '规则版本'=>'Rule version',
    '序列号'=>'Serial number',
    '系统版本'=>'System version',
    '系统操作'=>'System operation',
    '重启系统'=>'Reboot',
    '关闭系统'=>'Shutdown',
    '时间设置'=>'Time setting',
    '选择时间'=>'Select time',
    '当前时间'=>'Current time',
    '系统升级'=>'System upgrade',
    '软件版本号'=>'Software version',
    '升级文件'=>'Upgrade file',
    '规则升级'=>'Rule upgrade',
    '规则版本号'=>'Rule version',
    '配置备份恢复'=>'Configure backup recovery',
    '导出配置'=>'Export configuration',
    '导入配置'=>'Import configuration',
    '恢复默认设置'=>'Recover default settings',
    '恢复'=>'Recover',
    '网卡限速'=>'Network card speed limit',
    '速度'=>'Speed',
    '登录失败处理'=>'Logon failure processing',
    '失败次数'=>'Failure times',
    '次'=>'times',
    '次数'=>'times',
    '(次)'=>'times',
    '锁定时间'=>'Lock time',
    '分钟'=>'minutes',
    '密码安全策略'=>'Password security policy',
    '密码长度'=>'Password length',
    '密码复杂度'=>'Password complexity',
    '修改周期'=>'Modification cycle',
    '周期'=>'cycle',
    '天'=>'days',
    '字母和数字组合'=>'Combination of letters and numbers',
    '字母数字和特殊字符组合'=>'Alphanumeric and special character combinations',
    '自动退出设置'=>'Auto exit settings',
    '自动退出时间'=>'Auto exit time',
    '日志阀值设置'=>'Log threshold settings',
    '日志记录数量'=>'Log number',
    '记录条数'=>'Number of records',
    '日志警告百分比'=>'Log Warning Percentage',
    '自动备份数量'=>'Auto backup number',
    '扫描设置'=>'Scanning Settings',
    '允许登录的主机'=>'Host Allowed to Log In',
    '允许扫描的IP范围'=>'IP Range Allowed To Scan',
    '并发扫描任务数'=>'Concurrent Scanning Task Number',
    '例如'=>' For Example',
    '输入主机'=>'Input host ',
    'DNS服务器设置'=>'DNS Server Settings',
    '首选DNS服务器'=>'Preferred DNS Server',
    '备选DNS服务器'=>'Alternate DNS server',
    'ipv6首选DNS服务器'=>'IPv6 preferred DNS server',
    'ipv6备选DNS服务器'=>'IPv6 alternate DNS server',
    '接口配置'=>'Interface configuration',
    '接口名称'=>'Interface name',
    '子网掩码'=>'Subnet mask',
    'IPV6地址'=>'IPV6 address',
    'mac地址'=>'MAC address',
    '静态路由设置'=>'Static routing settings',
    '新增静态路由信息'=>'Add static routing information',
    '目的地址'=>'Destination address',
    '目的地址(ipv4)'=>'Destination address(ipv4)',
    '目的地址(ipv6)'=>'Destination address(ipv6)',
    '掩码'=>'Mask',
    '网关'=>'Gateway',
    '网关(ipv4)'=>'Gateway(ipv4)',
    '网关(ipv6)'=>'Gateway(ipv6)',
    '网关地址'=>'Gateway',
    '前缀'=>'prefix',
    'FTP服务配置'=>'FTP service configuration',
    'ftp服务器地址'=>'FTP server address',
    '路径'=>'Path',
    'SYSLOG配置'=>'SYSLOG configuration',
    '服务器地址'=>'Server address',
    'PPTP服务配置'=>'PPTP service configuration',
    'PPTP设置'=>'PPTP settings',
    'ip地址或域名'=>'IP address or domain name',
    '设置PPTP重连次数'=>'Set Number of Times For PPTP Reconnection',
    '重连时间间隔'=>'Interval For Reconnecting',
    '断线重连'=>'Reconnect If Disconnected',
    '秒'=>'Seconds',
    '连接'=>'Connect',
    '断开'=>'Disconnected',
    'PPTP状态'=>'PPTP state',
    '邮件服务器设置'=>'Mail server settings',
    '使用默认设置'=>'Use default settings',
    '清空日志'=>'Clear Log',
    '操作内容'=>'Operation Contents',
    '操作结果'=>'Operation result',
    '操作者'=>'Operator',
    '起止时间'=>'Start stop time',
    '至'=>'to',
    '导出结果'=>'Export results',
    '修改密码'=>'Edit pwd',
    '帮助'=>'help',
    '退出'=>'Logout',
    '版本'=>'version',
    '规则总数'=>'Sum of Rules',
    '主机'=>'Host',
    '弱密码'=>'Weak Password',
    '授权信息'=>'Authorization Information',
    '客户名称'=>'Customer Name',
    '授权类型'=>'Authorization Type',
    '授权开始时间'=>'Authorization Start Time',
    '授权结束时间'=>'Authorization End Time',
    '可扫描IP数量'=>'Max Number of Scanning IP',
    '个'=>'',
    '系统资源'=>'System Resource',
    'CPU利用率'=>'CPU Utilization',
    '内存利用率'=>'Memory Utilization',
    '硬盘利用率'=>'Disk Utilization',
    '网络利用率'=>'Network Utilization',
    '利用率'=>' Utilization',
    '内存'=>'Memory',
    '硬盘'=>'Disk',
    '网络'=>'Network',
    '蓝盾信息安全技术股份有限公司 版权所有'=>'Bluedon Information Security Technologies Co., Ltd All Rights Reserved',
    '中文'=>'Chinese',
    '基线扫描'=>'Baseline scan',
    '流量'=>'flow',
    '增加'=>'Add',
    '账号'=>' Username',
    '密钥分发中心'=>' Key distribution center',
    '认证类型'=>'Authentication type',
    '请选择'=>'Please select',
    '证书'=>' certificate',
    '提交设置'=>'Submit settings',
    '系统友情提示'=>'System friendly tips',
    '是否要删除数据'=>'Do you want to delete data?',
    '请选择数据'=>'Please select data',
    '请选择数据？'=>'Please select data',
    '查看主机扫描策略信息'=>'View the host scan policy information',
    '编辑主机扫描策略信息'=>'Edit host scan policy information',
    '确定是否退出系统'=>'Determine whether to exit the system',
    '退出成功'=>'Quit successfully',
    '退出失败'=>'Exit failed',
    '修改默认密码'=>'Modify default password',
    '是否确定退出系统？'=>'Are you sure you want to quit the system?',
    '操作成功'=>'Successful operation',
    '重复密码'=>'Repeat password',
    '正常'=>'normal',
    '停用'=>'disable',
    '系统管理员'=>'system administrator',
    '审计管理员'=>'Audit administrator',
    '用户'=>'user',
    '扫描任务数'=>'Number of scanning tasks',
    '表示不限'=>'Express no limitation',
    '换行可输入多个地址'=>'Line feed can enter multiple addresses',
    '禁止'=>'prohibit',
    'IP地址'=>'IP address',
    '策略备注'=>'Policy note',
    '角色名称'=>'Role name',
    '拥有权限'=>'Have permissions',
    '请在下面选择'=>'Please choose below',
    '请求失败'=>'request was aborted',
    '角色管理'=>'Role management',
    '管理操作'=>'Management operation',
    '帐号设置'=>'Account Settings',
    '查看权限'=>'View permissions',
    '增加角色配置信息'=>'Add role configuration information',
    '编辑角色配置信息'=>'Edit role configuration information',
    '是否删除'=>'Delete?',
    '此记录'=>'This record',
    '拥有的权限'=>'Ownership',
    '拥有如下打勾帐号'=>'You have the following account number',
    '是否要增加？'=>'Do you want to increase?',
    '增加成功'=>'Increase success',
    '已连接'=>'Connected',
    '已断开'=>'Disconnected',
    '以上各项均不能为空！'=>'None of the above is null',
    '密码过期'=>'Password expired',
    '密码已过期，请修改'=>'The password has expired. Please correct it',
    '数据不能为空'=>'Data cannot be empty',
    '规则升级中，请耐心等待...'=>'Please wait while the rules are updated...',
    '系统升级中，请耐心等待...'=>'Please wait while the system is upgraded...',
    '配置恢复中，请耐心等待...'=>'Please wait while the configuration is resumed...',
    '是否导出配置'=>'Export configuration?',
    '是否要更新系统时间'=>'Do you want to update your system time?',
    '是否关闭系统'=>'Shutting down the system?',
    '是否恢复默认配置'=>'Do you want to restore the default configuration?',
    '是否重启系统'=>'Reboot system',
    '请选择时间'=>'Please select time',
    '修改时间可能会导致系统出错,是否继续?'=>'Modification time may cause system error. Do you want to continue?',
    '登陆账号'=>'Login account',
    '特权密码'=>'Privileged password',
    '选择规范'=>'Selection specification',
    '执行方式'=>'Execution mode',
    '立即执行'=>'Immediate execution',
    '某个时刻执行'=>'Execute at some point',
    '每天一次'=>'Once a day',
    '每周一次'=>'Once a week',
    '每月一次(按日期)'=>'Once a month (by date)',
    '每月一次(按星期)'=>'Once a month (by week)',
    '日'=>'Sunday',
    '一'=>'Monday',
    '二'=>'Tuesday',
    '三'=>'Wednesday',
    '四'=>'Thursday',
    '五'=>'Friday',
    '六'=>'Saturday',
    '执行时间'=>'execution time',
    '第'=>'the ',
    '1'=>'One',
    '2'=>'Two',
    '3'=>'Three',
    '4'=>'Four',
    '任务说明'=>'Task description',
    '是否开启'=>'Whether to open',
    '运行间隔'=>'Running interval',
    '请先到系统管理'=>'Please go to system management first',
    '服务设置'=>'Service settings',
    'ftp服务配置'=>'FTP service configuration',
    '(0表示不限)'=>'(0 means unlimited)',
    '代理登录'=>'Proxy login',
    '预设cookie'=>'Preset cookie',
    '账号密码'=>'Account password',
    '代理设置'=>'Proxy settings',
    '代理扫描必须按照提示设置代理'=>'The proxy scan must set the proxy as prompted',
    '设置完代理并登录访问当前要扫描网站'=>'Set up the agent and log in to access the current web site',
    '登录之后至少访问3个页面'=>'Access at least 3 pages after logging in',
    '测试完毕之后关闭代理'=>'Close the agent after the test has been completed',
    '请输入cookie,可查看浏览器请求头元素获取'=>'Please enter cookie to see the browser request header elements to get',
    '登录参数'=>'Logon parameter',
    '登录URL'=>'Login URL',
    '测试URL'=>'Test URL',
    '必须是要登陆之后才能访问的url'=>'Must be the URL that can be accessed after landing',
    '登录测试'=>'Login test',
    '代理配置指南'=>'Proxy Configuration Guide',
    '此处将会动态显示正在扫描的任务及IP'=>'The tasks and IP being scanned are dynamically displayed here',
    '漏洞总计(高/中/低/总)'=>'Total vulnerabilities (high / medium / low / total)',
    '全部'=>'All',
    '未扫描'=>'Not scanned',
    '扫描中'=>'Scanning',
    '已扫描'=>'Scanned',
    '暂停扫描'=>'Pause scan',
    '风险分析'=>'Risk analysis',
    '任务状态'=>'Task status',
    '主机漏洞'=>'Host vulnerability',
    'web漏洞'=>'Web vulnerability',
    '弱密码漏洞'=>'Weak password vulnerability',
    '步骤'=>'step',
    '点击开始菜单，打开【控制面板】'=>'Click on the start menu to open [control panel]',
    '点击选择【Internet选项】'=>'Click Select [Internet options]',
    '切换到【连接】，点击【局域网设置】'=>'切换到【连接】，点击【局域网设置】',
    '编辑代理服务器，输入以下ip和端口'=>'Edit the proxy server and enter the following IP and ports',
    '按风险级别'=>'By risk level',
    '按扫描类型'=>'By scan type',
    '按ip历史漏洞统计'=>'According to IP historical vulnerability statistics',
    '评估等级'=>'Rating',
    '跃点数'=>'Metric',
    '开 始'=>'Start',
    '进度'=>'Progress',
    '添加到扫描任务'=>'Add to scan task',
    '一键全部添加到右侧'=>'Add all of the keys to the right',
    '默认值为'=>'The default value is ',
    '远程协助弱密码字典'=>'Remote assistance weak password dictionary',
    '字典格式：“用户名:密码”，每行一条记录，用户名及密码均不允许出现“:”号'=>'Dictionary format: "user name: password", each line of a record, user name and password are not allowed to appear ":"',
    '描述'=>'Describe',
    '解决方案'=>'Solution',
    'WEB地址'=>'WEB address',
    '部门漏洞数统计'=>'Sector vulnerability statistics',
    '资产漏洞数统计'=>'Asset vulnerability statistics',
    '上传失败！'=>'Upload failed!',
    '其它'=>'Other',
    'Cisco路由器'=>'Cisco routers',
    'Cisco交换机'=>'Cisco switch',
    '请选择漏洞'=>'Please select vulnerability',
    '紧急'=>'Urgent',
    '提交中...'=>'Submission...',
    '至少保留一项选中！'=>'Keep at least one item selected!',
    '漏洞详细信息'=>'Vulnerability details',
    '不能删除全扫策略或快扫策略，或者此策略已在任务中'=>'You cannot delete the full sweep policy or the quick sweep policy, or this policy is already in the task',
    '是否要删除数据？'=>'Do you want to delete data?',
    'Windows证书'=>'Windows certificate',
    'Kerberos配置'=>'Kerberos configuration',
    '操作时间'=>'Operating time',
    '开始时间不能大于结束时间'=>'The start time must not be greater than the end time',
    '是否导出日志'=>'Export logs?',
    '存放生成文件的目录,需要可写权限'=>'Storing the generated files requires permission to write',
    '是否要删除所有日志数据？'=>'Do you want to delete all log data?',
    '备份文件名称'=>'Backup file name',
    '文件生成时间'=>'File generation time',
    '是否要导出备份文件？'=>'Do you want to export backup files?',
    '是否导出备份日志'=>'Export backup logs?',
    '编辑扫描端口策略信息'=>'Edit scan port policy information',
    '查看端口策略信息'=>'View port policy information',
    '不能删除默认端口策略，或者此端口策略已在任务中'=>'The default port policy cannot be deleted, or this port policy is already in the task',
    '点击解锁'=>'Click unlock',
    '锁定'=>'locking',
    '点击禁止'=>'Click inhibit',
    '点击恢复正常'=>'Click back to normal',
    '请选择某一行数据？'=>'Please select a row of data',
    '编号id'=>'Serial number ID',
    '编辑弱密码策略信息'=>'Edit weak password policy information',
    '查看弱密码策略信息'=>'View weak password policy information',
    '不能删除默认弱密码策略，或者此策略已在任务中'=>'The default weak password policy cannot be deleted, or this policy is already in the task',
    '字典格式：“密码”，每行一条记录。'=>'Dictionary format: password, one line per line.',
    '字典格式：“用户名:密码”，每行一条记录，用户名及密码均不允许出现“:”号。'=>'Dictionary format: "user name: password", each line of a record, user name and password are not allowed to appear ":" number.',
    '行'=>'line',
    '不能删除默认web策略，或者此策略已在任务中'=>'The default web policy cannot be deleted, or this policy is already in the task',
    '编辑WEB应用策略信息'=>'Edit WEB application policy information',
    '查看WEB应用策略信息'=>'View WEB application policy information',
    '数量'=>'Number',
    '未登记资产'=>'Unregistered assets',
    '资产任务'=>'Asset task',
    '序号'=>'Serial number',
    '名称'=>'name',
    '漏洞总数'=>'Total vulnerabilities',
    '高风险漏洞'=>'high',
    '中风险漏洞'=>'medium',
    '低风险漏洞'=>'low',
    '无风险漏洞'=>'information',
    '风险分布图'=>'Risk distribution map',
    '所有资产最新扫描结果'=>'Latest scan of all assets',
    '最新扫描结果'=>'Latest scan results',
    '是否要删除资产？'=>'Do you want to delete assets?',
    '请选择资产？'=>'Please select assets',
    '请选择要操作的行？'=>'Please select the line you want to operate on',
    '确定扫描该部门全部的资产？'=>'Make sure to scan all of the assets of the Department',
    '是否要导出资产？'=>'Do you want to export assets?',
    '点击下载数据'=>'Click download data',
    '通用设备'=>'General equipment',
    '最新扫描时间'=>'Latest scan time',
    '查看'=>'view',
    '近期扫描-风险评估趋势'=>'Recent scan - risk assessment trends',
    '高风险数'=>'High risk number',
    '中风险数'=>'Medium risk number',
    '低风险数'=>'Low risk number',
    '总信息数'=>'Information number',
    '风险评估等级'=>'Risk assessment level',
    '没有相关部门扫描'=>'No relevant department scans',
    '风险评估趋势'=>'Risk assessment trends',
    '数'=>'numbers',
    '拓扑图任务'=>'Topological graph task',
    '添加排除端口'=>'Add exclude port',
    '编辑任务信息'=>'Edit task information',
    '查看任务信息'=>'View task information',
    '获取部门失败'=>'Get department failure',
    '按住Ctrl或Shift键可选多个'=>'Press Ctrl or Shift key to select more than one',
    '报表条件'=>'Report condition',
    '扫描内容'=>'Scanning content',
    '综述'=>'Overview',
    '漏洞等级'=>'Vulnerability level',
    '扫描类型'=>'Scan Type',
    '核查配置'=>'Config Check',
    '配置核查'=>'Config Check',
    '正在搜索，请稍等几秒...'=>'Searching, please wait a few seconds...',
    '请先输入目标！'=>'Please enter the target first!',
    '搜索程序已异常结束！'=>'The search program has ended abnormally!',
    '点击展现改网段的所有ip节点'=>'Click on all IP nodes that display the segment',
    '扩展点'=>'Extension node',
    '空节点'=>'Empty node',
    '等级'=>'level',
    '自己_安全'=>'self_safe',
    '未开始' => 'Not starting',
    '未结束' => 'Not finished',
    '蓝盾安全扫描系统' => 'Bluedon Security Scanning System',
    '的安全评估' => 'security assessment',
    '导出报表' => 'Export report',
    '导出成功' => 'Export success',
    '导出失败' => 'Export failed',
    '高危' => 'High',
    '中危' => 'Medium',
    '低危' => 'Lower',
    '按ip' => 'By ip',
    '本次扫描没有发现该风险。' => 'Not found the vulnerability at this scanning.',
    '本次扫描共发现该风险' => 'Found the vulnerabilities amount',
    '风险评级' => 'Vulnerability level',
    '风险名称' => 'Vulnerability name',
    '影响主机数' => 'The number of effected hosts',
    '更多信息' => 'More',
    '展开详情' => 'Detail',
    '影响URL数' => 'The number of effected URLs',
    'URL列表（共' => 'URL list(',
    '项）' => ')',
    '风险描述' => 'Vulnerability description',
    '弱密码类型' => 'Weak password',
    '相关编号' => 'related number',
    '参考信息' => 'Reference information',
    '总体风险分析' => 'Overall vulnerabilities analysis',
    '风险等级分布' => 'The distribution of vulnerability level',
    '风险类型分布' => 'The distribution of vulnerability type',
    '所有主机（IP）风险分布' => 'The vulnerability distribution of all host (IP)',
    '主机漏洞列表' => 'A list of host vulnerabilities',
    '系统漏洞' => 'System vulnerabilities',
    '服务漏洞' => 'Server vulnerabilities',
    '应用漏洞' => 'Application vulnerabilities',
    '网络设备漏洞' => 'Web device vulnerabilities',
    '数据库漏洞' => 'Database vulnerabilities',
    '虚拟化平台漏洞' => 'virtual platform vulnerabilities',
    'WEB漏洞列表' => 'The list of WEB vulnerabilities',
    '系统命令执行' => 'System command execution',
    'SQL注入' => 'SQL  injection',
    '代码远程执行' => 'Execute code by remotely',
    '远程文件包含' => 'Include remote files',
    'HTTP参数污染' => 'HTTP',
    'LDAP注入' => 'LDAP injection',
    '跨站脚本攻击' => 'XSS',
    '内容欺骗' => 'Content spoofing',
    '文件上传' => 'Upload files',
    '拒绝服务' => 'Refuse service',
    '信息泄露' => 'Information leakage',
    '目录遍历' => 'Traver directories',
    '日志文件扫描' => 'Scanning log files',
    '软件服务检测' => 'Software service detection',
    '任意文件读取' => 'Read any files',
    '数据库发现' => 'Found database',
    '后门发现' => 'Found backdoor',
    '验证绕过' => 'Bypass verification',
    '配置不当' => 'Configuration wrong',
    '弱密码漏洞列表' => 'The list of weak password vulnerabilities',
    '请选择任务.' => 'Please select task. ',
    '请填写报表名称.' => 'Please fill the name',
    '本次扫描共发现弱密码' => 'Found the weak password amount',
    '影响主机' => 'Effecting host',
    '个。' => '. ',
    '个，' => ', ',
    '域名' => 'Domain',
    '输出详情：' => 'Output detail: ',
    '已存在，请更换' => 'Existing, please replace',
    '编辑主机扫描策略' => 'Edit host scanning policy',
    '添加主机扫描策略' => 'Add host scanning policy',
    '删除主机扫描策略' => 'Delete host scanning policy',
    '名称已存在' => 'The name is existed',
    '操作失败' => 'Fail',
    '失败' => 'Fail',
    '成功' => 'Success',
    '失败，名称（' => 'Failed, name(',
    '已存在' => 'Existed',
    '后台创建主机扫描策略失败' => 'It is failed to creating host scanning policy by background',
    '后台删除主机扫描策略失败' => 'It is failed to delete host scanning policy by background',
    '快扫主机策略' => 'Fast scanning host policy',
    '预设快扫主机策略成功' => 'It is successful to preset fast scanning host policy',
    '预设快扫主机策略失败' => 'It is failed to preset fast scanning host policy',
    '编辑快扫主机策略' => 'Edit fast scanning host policy',
    '后台编辑快扫主机策略' => 'Edit fast scanning host policy by background',
    '后台编辑快扫主机策略失败' => 'It is failed to edit fast scanning policy by background',
    '新增快扫主机策略' => 'Add fast scanning host policy',
    '设置快扫主机策略' => 'Setting fast scanning host policy',
    '全部主机策略' => 'All host policies',
    '预设全部主机策略成功' => 'It is successful to preset all host policies',
    '预设全部主机策略失败' => 'It is failed to preset all host policies',
    '编辑全部主机策略' => 'Edit all host policies',
    '后台编辑全部主机策略' => 'Edit all host policies by background',
    '后台编辑全部主机策略失败' => 'It is failed to edit all host policies',
    '后台编辑全部主机策略成功' => 'It is successful to edit all host policies',
    '新增全部主机策略' => 'Add all host policies',
    '设置全部主机策略' => 'Set all host policies',
    '后台新增全部主机策略' => 'Add all host policy by background',
    '所有漏洞' => 'All vulnerabilities',
    '符合规范' => 'It is legal',
    '合规检查项数' => 'The amount of valid inspect',
    '不合规检查项数' => 'The amount of invalid inspect item',
    '每月一次（按日期）' => 'Once a month(by date)',
    '每月一次（按星期）' => 'Once a month(by week)',
    '毫秒' => 'Millisecond',
    '时' => 'Hour',
    '分' => 'Minute',
    '添加设备和规范' => 'Add device and standard',
    '添加设备和规范失败' => 'It is failed to add device and standard',
    '成功添加设备和规范' => 'It is successful to add device and standard',
    '增加任务成功' => 'It is successful to add task',
    '新增任务失败' => 'It is failed to add the new task',
    '编辑任务成功' => 'It is successful to edit task',
    '编辑任务失败' => 'It is failed to edit task',
    '编辑基线任务' => 'Edit baseline task',
    '新增基线任务' => 'Add baseline task',
    '删除任务成功' => 'It is successful to delete baseline task',
    '删除基线任务' => 'Delete baseline task',
    'dns地址' => 'dns address',
    '不合法' => 'illegal',
    'ipv6地址格式错误' => 'ipv6 address format error',
    'ipv4地址格式错误' => 'ipv4 address format error',
    '子网掩码格式错误' => 'Net mask format error',
    'ipv6前缀必须在1~127的范围内' => 'The prefix of ipv6 must in the range of 1 and 127',
    '网口更新' => 'Update net port',
    '创建成功' => 'Created successfully',
    '网口创建' => 'Create net port',
    '删除日志' => 'Delete log',
    '清空所有日志' => 'Empty all of the log',
    '删除备份日志' => 'Delete backup log',
    '编辑角色' => 'Edit ruler',
    '新增角色' => 'Add ruler',
    '该角色还有子角色存在，不能删除。' => 'Can not delete because of the sub ruler is existed',
    '该角色有用户存在，不能删除。请删除用户在删除该角色！' => 'The ruler has users, you can not delete. Please delete the users firstly',
    '删除角色成功' => 'Delete ruler successfully',
    '请求数据失败' => 'Request data fail',
    '请输入端口号' => 'Please input the port number',
    '是非法端口' => 'It is illegal port',
    '编辑扫描端口策略' => 'Edit scan port policy',
    '后台编辑扫描端口失败' => 'It is failed to edit scan port by background',
    '后台创建扫描端口失败' => 'It is failed to create scan port by background',
    '新增扫描端口策略成功' => 'Add scan port policy successfully',
    '快扫端口' => 'Fast scan port',
    '预设成功' => 'Preset successfully',
    '预设失败' => 'Preset unsuccessfully',
    '编辑扫描端口策略成功' => 'Edit scan port policy successfully',
    'ftp配置' => 'ftp configuration',
    'pptp配置' => 'pptp configuration',
    'ip地址' => 'ip address',
    '蓝盾安全漏洞扫描系统' => 'Bluedon security vulnerability scan system',
    '被禁止的ip，不允许登录' => 'The ip is forbidden, you can sign in',
    '用户登录' => 'User login',
    '用户已锁' => 'User locked',
    '分钟后重新登录' => 'minute login again',
    '失败，账号已被锁定' => 'It is failed, the account has been locked',
    '验证码错误' => 'Verify code error',
    '失败，验证码错误' => 'Failed, verify code error',
    '用户名或密码错误' => 'Username or password error',
    '用户已被禁止登录' => 'The user has been forbidden to login',
    '账号已被禁止' => 'The account is forbidden',
    '账号已被锁定' => 'The account is locked',
    '登录成功' => 'Login successfully',
    'CPU使用率' => 'CPU utilization rate',
    '内存使用率' => 'Memory utilization rate',
    '硬盘使用率' => 'Disks utilization rate',
    '账号或密码错误' => 'Account or password error',
    '密码错误' => 'Password error',
    '退出系统' => 'Exit',
    '前缀（ipv6）必须在1~127的范围内' => 'The suffix of ipv6 must in range 1 and 127',
    '网关（ipv6）格式错误' => 'The gateway (ipv6) format error',
    '已经有相同的静态路由' => 'The static route is existed',
    '编辑静态路由' => 'Edit static route',
    '已存在默认路由' => 'The default route is existed',
    '添加失败' => 'Add failed',
    '编辑路由失败' => 'Edit route failed',
    '新增静态路由失败' => 'Add static route failed',
    '添加默认路由失败' => 'Add default route failed',
    '删除静态路由' => 'Delete static route',
    '登录失败设置' => 'The setting of login failed',
    'SNMP设置' => 'SNMP setting',
    '日志数据存储量已经达到阀值,请导出备份数据或者清除部分数据！' => 'Log saved data has reach threshold, please backup or clear part of data! ',
    '第 ' => 'The ',
    '行ip格式错误' => 'row ip format error',
    '导出系统配置' => 'Export system setting',
    '下载导出文件' => 'Download exported file',
    '恢复成功！' => 'Recovery successfully! ',
    '授权码错误' => 'Authorization code error',
    '升级成功。' => 'Update successfully.',
    '系统升级成功' => 'Update system successfully',
    '系统升级失败' => 'Update system failed',
    '升级失败，请检查/preupgrade目录是否存在' => 'Update failed, please check the directory /preupgrade whether is existed',
    '升级文件格式不对，请联系管理员。' => 'The format of upgrade file is error, please contact administrators',
    '文件格式不对' => 'The file format error',
    '升级的文件太大，请联系管理员。' => 'The file is too large, please contact the administrators.',
    '升级的文件太大' => 'The upgrade file is too large',
    '升级文件格式不对' => 'The format of upgrade file is error',
    '文件不能为空' => 'The file can not be empty',
    '规则升级失败' => 'Update the rule failed',
    '正在检测' => 'It is checking now',
    '登录域名必须包含在扫描对象的域名中！' => 'The login name must be included at the domain of the scan project!',
    'html文件不存在，操作失败' => 'Fail, the html file does not exist',
    '请勿输入相同的ip' => 'Please don not input the same ip',
    '请检查输入ip,是否已重复' => 'Please check the input ip, whether exist the same one',
    '启用pptp时，不允许扫描同一网段' => 'When start the pptp, can not scanning the same network segment',
    '请勿输入相同的域名' => 'Please don not input the same domain',
    '新增扫描任务成功' => 'Add scan task successfully',
    '新增扫描任务失败' => 'Add scan task failed',
    '后台创建任务失败' => 'It is failed to create task by background',
    '可扫描IP数量不能超过' => 'The amount of scan ip can not more than',
    '编辑扫描任务' => 'Edit scan task',
    '编辑成功' => 'Edit successfully',
    '编辑失败' => 'Edit failed',
    '后台编辑任务失败' => 'Edit task failed by background',
    '后台编辑任务' => 'Editing task by background',
    '删除任务' => 'Delete task',
    '删除成功' => 'Delete successfully',
    '主机扫描结果' => 'The result of host scan',
    'WEB扫描结果' => 'The result of WEB scan',
    '弱密码扫描结果' => 'The result of weak password scan',
    '主机列表' => 'Host list',
    'WEB漏洞' => 'WEB vulnerabilities',
    '类型' => 'type',
    '数据库' => 'database',
    '匿名用户' => 'Anonymous user',
    '没有相关风险结果' => 'Having no result of related vulnerabilities',
    '邮箱地址格式不正确' => 'Email address format error',
    '修改任务成功' => 'Change task successfully',
    '保存任务成功' => 'Save task successfully',
    '扫描对象：批量域名不能多于10' => 'Scan object: the batch domain can not more than 10',
    '扫描对象：批量域名第' => 'Scan object: the batch domain of the',
    '行格式错误' => 'row, format error',
    ' 行格式错误' => ' row, format error',
    '扫描线程不能为空!' => 'The scan thread can not be empty! ',
    '扫描超时不能为空!' => 'The scan timeout can not be empty! ',
    '任务名已存在' => 'The task name is existed',
    '新增任务成功' => 'Add task successfully',
    '小时' => 'hour',
    '周' => 'week',
    '月' => 'month',
    '扫描对象：批量IP第' => 'Scan object: the batch IP of the',
    '行不在允许扫描的IP范围内' => 'row, is out of the allowed ip',
    '行网段包含了本机IP' => 'row, network segment include the local IP',
    '行格式错误，不能跨网段扫描' => 'row, format error, can not scan cross the network segment',
    '扫描对象：批量IPV4第' => 'Scan object: the batch IPV4 of the',
    '扫描对象：批量IPV6第' => 'Scan object: the batch IPV6 of the',
    '扫描对象不能为空' => 'The scan object can not be empty',
    '数据异常' => 'Data abnormal',
    '登录异常' => 'Login abnormal',
    '自动扫描' => 'Scan automatically',
    '手动扫描' => 'Scan manually',
    '基本配置：请修改"扫描端口超时"在1至120范围之内' => 'Basic configuration: please set the "scan port timeout" in range of 1 and 120',
    '基本配置：请修改"扫描端口线程"在1至120范围之内' => 'Basic configuration: please set the "scan port thread" in range of 1 and 120',
    '批量域名不能大于500行' => 'The row of batch domain can not more than 500',
    '批量IP不能大于500行' => 'The row of bath IP can not more than 500',
    '请选择主机策略' => 'Please select host policy',
    '主机扫描配置：请修改"扫描超时"在5至50000范围之内' => 'Host scan configuration: please set the "scan timeout" in range 5 and 50000',
    '主机扫描配置：请修改"主机线程数"在1至100范围之内' => 'Host scan configuration: please set the "host thread amount" in range 1 and 100',
    '主机扫描配置：请修改"并发主机数"在1至200范围之内' => 'Host scan configuration: please set the concurrent',
    '请选择WEB策略' => 'Please select WEB policy',
    'web扫描配置：请修改"每分钟请求URL数"在1至10000范围之内' => 'web scan configuration: please set "the amount of Request URL a minute" in range of 1 and 10000',
    'web扫描配置：请修改"扫描线程"在1至10范围之内' => 'web scan configuration: please set "the scan thread" in range of 1 and 10',
    'web扫描配置：请修改"爬虫地址数"在1至99999999范围之内' => 'web scan configuration: please set "the spider url amount" in range of 1 and 99999999',
    'web扫描配置：请修改"扫描超时"在1至120范围之内' => 'web scan configuration: please set "the scan timeout" in range of 1 and 120',
    'web扫描配置：请修改"获取域名超时"在1至120范围之内' => 'web scan configuration: please set "get domain timeout" in range of 1 and 120',
    'web扫描配置：请修改"通信异常请求次数"在1至10范围之内' => 'web scan configuration: please set "request abnormally times" in range of 1 and 10',
    'web扫描配置：请修改"通信异常请求间隔"在1至60范围之内' => 'web scan configuration: please set "request abnormally interval" in range of 1 and 60',
    '请选择弱密码策略' => 'Please select weak password policy',
    '弱口令扫描配置：请修改"扫描线程"在1至20范围之内' => 'Weak password scan configuration: please set "scan thread" in range 1 and 20',
    '弱口令扫描配置：请修改"扫描超时"在1至600范围之内' => 'Weak password scan configuration: please set "scan timeout" in range 1 and 600',
    '编辑模板成功' => 'Edit template successfully',
    '新增失败' => 'Add failed',
    '新增成功' => 'Add successfully',
    '新增模板成功' => 'Add template successfully',
    '删除模板成功' => 'Delete template successfully',
    '无数据' => 'No data',
    '指令为空或类型不对' => 'Directive is empty or type error',
    '指令参数不正确' => 'Directive parameters error',
    '没有返回结果' => 'No result',
    'IP或域名不正确' => 'IP or domain error',
    '即将输出结果' => 'The result will be output right now',
    '配置成功！' => 'Config successfully!',
    '配置失败！' => 'config failed!',
    '输入格式不正确！请按正确格式输入！' => 'The format of input is error! Please input the correct format!',
    '未知网段' => 'Unknow network segment',
    '内置用户不能编辑' => 'The built-in user can not edit',
    '编辑内置用户' => 'Edit built-in user',
    '无权限' => 'No permission',
    '删除用户中含有内置用户' => 'The deleted user include built-in user',
    '删除用户' => 'Delete user',
    '删除用户中含有内置用户，删除失败。' => 'Delete failed, the deleted user include built-in user',
    '内置用户不能删除' => 'Can not delete built-in user',
    '删除内置用户' => 'Delete built-in user',
    '请选择用户！' => 'Please select user!',
    '不允许使用初始密码！' => 'Can not use initial password',
    '密码长度不能小于' => 'The length of password can not less than',
    '密码长度不能大于20个字符' => 'The length of password can not more than 20',
    '密码必须是字母和数字组合' => 'The password must be combined with alphabetic and digit',
    '密码必须是字母数字和特殊字符组合' => 'The passoword must be combined with alphanumeric and special string',
    '修改' => 'Modify',
    '密码成功' => 'password successfully',
    '输入的旧密码错误！' => 'The input old password error!',
    '新旧密码不能相同！' => 'The new password can not be the same as the old password',
    'windows远程协助' => 'windows remote assistance',
    '编辑弱密码策略' => 'Edit weak password policy',
    '失败，名称(' => 'Failed, name (',
    ')已存在' => ') existed',
    '后台创建弱密码策略失败' => 'Create weak password policy failed by background',
    '文件内容不允许使用中文' => 'The file content is not allowed to use Chinese',
    '更新弱口令参数' => 'Update weak password parameter',
    '导入文件内容不允许使用中文' => 'The content of import file can not use Chinese',
    '导入文件' => 'Import file',
    '上传失败' => 'Upload failed',
    '上传成功' => 'Upload successfully',
    '导入弱口令字典' => 'Import weak password dictionary',
    '请上传UTF-8编码格式的文件' => 'Please the file that coding with UTF-8',
    '请选择文件后缀名为config的文件' => 'Please select the file that the suffix is config',
    '请选择文件' => 'Please select file',
    '恢复失败' => 'Recovery failed',
    'web配置已经达到或者超过1024条，不能继续添加' => 'Can not add, due to the web configuration is equal to or more than 1024',
    '编辑WEB应用扫描策略' => 'Edit WEB application scan policy',
    '删除WEB扫描策略' => 'Delete WEB scan policy',
    '没有相关资产扫描' => 'There are no related asset to scan',
    '没有相关扫描' => 'There are no related scan',
    '没有添加相关任务' => 'No adding the related task',
    '编辑任务' => 'Edit asset',
    'MAC地址格式错误！' => 'MAC address format error!',
    '修改成功' => 'Edit successfully',
    '修改资产' => 'Edit asset',
    '编辑资产' => 'Edit asset',
    '连接失败' => 'Connect failed',
    '连接成功' => 'connect successfully',
    '连接出错' => 'Connect error',
    '同时扫描任务数不能超过' => 'The task amount that scanning at the same time can not more than',
    '个 ' => '',
    '可以扫描新任务' => 'Can scan new task',
    '添加失败,该任务已经存在！' => 'Add failed, the task is existed!',
    '添加失败,该部门没资产！' => 'Add failed, the department has no asset!',
    '添加成功' => 'Add successfully',
    '新增主机扫描任务' => 'Add host scan task',
    '操作成功，已删除部门，同时删除了相应资产' => 'It is successfully to delete the department and the related asset',
    '删除部门' => 'Delete department',
    '同时删除了相应资产' => 'delete the related asset at the same time',
    '已删除部门，但是相应资产没能成功删除' => 'Delete department, but delete the related asset failed',
    '但是保留了相应资产' => 'but retained the related asset',
    '操作成功，已删除部门，该部门资产转入未登记资产' => 'Successfully, the department is deleted, and the asset of the department is changed to unregistered asset',
    '该部门资产转入未登记资产' => 'The asset of the department is changed to unregistered asset',
    '开放端口' => 'Open port',
    '交换机' => 'Switches',
    '路由器' => 'router',
    '请上传Excel文件' => 'Please upload Excel file',
    '行的所属部门、负责人和IPV4都不能为空！' => 'row, department, persion in charge and IPV4 can not be empty!',
    ' 行，资产标识 ' => 'row, asset identification',
    ' 已经存在！' => 'existed!',
    '上传失败！请严格按模板填写！' => 'Upload failed! Please take care to follow the template to fill in it!',
    '上传成功！' => 'Upload successfully!',
    '但是部分上传失败: ' => 'but the part of uploading failed: ',









































































];