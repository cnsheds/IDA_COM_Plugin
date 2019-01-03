
#include "Common.h"

// Hex-Rays API pointer
hexdsp_t *hexdsp = NULL;


uint str2int(qstring& str)
{
	uint ret = 0;
	char *stop;
	if (str.substr(0, 2) == "0x")
	{
		ret = strtol(str.substr(2).c_str(), &stop, 16);
	}
	else
	{
		ret = strtol(str.c_str(), &stop, 10);
	}

	return ret;
}

void get_string(ea_t ea, qstring &strdst)
{
	flags_t flags = get_flags(ea);
	opinfo_t op;
	auto strtype = STRTYPE_C;
	auto ok = !!get_opinfo(&op, ea, 0, flags);
	if (ok)
	{
		strtype = op.strtype == -1 ? STRTYPE_C : op.strtype;
	}

	const auto n = get_max_strlit_length(ea, strtype, ALOPT_IGNHEADS);
	if (n)
		const auto ntxt = get_strlit_contents(&strdst, ea, n, strtype);
}


qstring get_expr_name(cexpr_t *e)
{
	if (!e)
		return "";

	char lbuf[MAXSTR] = "";
	e->y->print1(lbuf, sizeof(lbuf), NULL);
	qstring qbuf(lbuf);
	tag_remove(&qbuf);

	return qbuf;
}

bool get_expr_name(citem_t *citem, qstring& rv)
{
	if (!citem->is_expr())
		return false;

	cexpr_t *e = (cexpr_t *)citem;

	// retrieve the name of the routine
	char citem_name[MAXSTR] = {};
	e->print1(citem_name, _countof(citem_name) - 1, NULL);
	rv = citem_name;
	tag_remove(&rv);

	return true;
}

void setUnknown(ea_t ea, int size)
{
	// TODO: Does the overrun problem still exist?
	//do_unknown_range(ea, (size_t)size, DOUNK_SIMPLE);
	while (size > 0)
	{
		int isize = get_item_size(ea);
// 		if (isize > size) 
// 			break;	//因为有些结构后面会有连续的0, 这样将造成后面的0没有Unknow, 结果建立结构将失败

		{
			del_items(ea, DELIT_SIMPLE);
			ea += (ea_t)isize, size -= isize;
		}
	};
}


// Wrapper for 'add_struc_member()' with error messages
// See to make more sense of types: http://idapython.googlecode.com/svn-history/r116/trunk/python/idc.py
int addStrucMember(struc_t *sptr, char *name, ea_t offset, flags_t flag, opinfo_t *type, asize_t nbytes)
{
	int r = add_struc_member(sptr, name, offset, flag, type, nbytes);
	switch (r)
	{
	case STRUC_ERROR_MEMBER_NAME:
		msg("AddStrucMember(): error: already has member with this name (bad name)\n");
		break;

	case STRUC_ERROR_MEMBER_OFFSET:
		msg("AddStrucMember(): error: already has member at this offset\n");
		break;

	case STRUC_ERROR_MEMBER_SIZE:
		msg("AddStrucMember(): error: bad number of bytes or bad sizeof(type)\n");
		break;

	case STRUC_ERROR_MEMBER_TINFO:
		msg("AddStrucMember(): error: bad typeid parameter\n");
		break;

	case STRUC_ERROR_MEMBER_STRUCT:
		msg("AddStrucMember(): error: bad struct id (the 1st argument)\n");
		break;

	case STRUC_ERROR_MEMBER_UNIVAR:
		msg("AddStrucMember(): error: unions can't have variable sized members\n");
		break;

	case STRUC_ERROR_MEMBER_VARLAST:
		msg("AddStrucMember(): error: variable sized member should be the last member in the structure\n");
		break;

	case STRUC_ERROR_MEMBER_NESTED:
		msg("AddStrucMember(): error: recursive structure nesting is forbidden\n");
		break;
	};

	return(r);
}

void logmsg(unsigned int level, const char *fmt, ...)
{
	va_list arglist;

	if (level > CURRENT_DEBUG_LEVEL)
		return;

	va_start(arglist, fmt);
	vmsg(fmt, arglist);
	va_end(arglist);
}

std::string get_procname()
{
	std::string cpuname = inf.procname;
	std::transform(cpuname.begin(), cpuname.end(), cpuname.begin(), tolower);
	return cpuname;
}

ea_t get_aword(ea_t addr)
{
	if (inf.is_64bit())
		return get_qword(addr);
	else
		return get_dword(addr);
}

std::string MBCS2UTF8(char *szGbk)
{
	std::string retstr;
	// 先将多字节GBK（CP_ACP或ANSI）转换成宽字符UTF-16
	// 得到转换后，所需要的内存字符数
	int n = MultiByteToWideChar(CP_ACP, 0, szGbk, -1, NULL, 0);
	// 字符数乘以 sizeof(WCHAR) 得到字节数
	WCHAR *str1 = new WCHAR[sizeof(WCHAR) * n];
	// 转换
	MultiByteToWideChar(CP_ACP,  // MultiByte的代码页Code Page
						0,            //附加标志，与音标有关
						szGbk,        // 输入的GBK字符串
						-1,           // 输入字符串长度，-1表示由函数内部计算
						str1,         // 输出
						n             // 输出所需分配的内存
	);

	// 再将宽字符（UTF-16）转换多字节（UTF-8）
	n = WideCharToMultiByte(CP_UTF8, 0, str1, -1, NULL, 0, NULL, NULL);
	char* szUtf8 = new char[n + 1];
	WideCharToMultiByte(CP_UTF8, 0, str1, -1, szUtf8, n, NULL, NULL);
	delete[] str1;
	str1 = NULL;
	retstr = szUtf8;
	delete[] szUtf8;
	return retstr;
}

//UTF-8 GBK
std::string UTF82MBCS(char *szUtf8)
{
	std::string retstr;
	int n = MultiByteToWideChar(CP_UTF8, 0, szUtf8, -1, NULL, 0);
	WCHAR * wszGBK = new WCHAR[sizeof(WCHAR) * n];
	memset(wszGBK, 0, sizeof(WCHAR) * n);
	MultiByteToWideChar(CP_UTF8, 0, szUtf8, -1, wszGBK, n);

	n = WideCharToMultiByte(CP_ACP, 0, wszGBK, -1, NULL, 0, NULL, NULL);

	char* szGbk = new char[n + 1];
	WideCharToMultiByte(CP_ACP, 0, wszGBK, -1, szGbk, n, NULL, NULL);

	delete[]wszGBK;
	wszGBK = NULL;
	retstr = szGbk;
	delete[] szGbk;
	return retstr;
}