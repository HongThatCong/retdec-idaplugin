#include <sstream>

#include "function.h"

Function::Function() {}

Function::Function(func_t* f, const std::vector<Token>& tokens) : m_p_func_t(f)
{
    std::size_t y = YX::starting_y;
    std::size_t x = YX::starting_x;
    for (auto& t : tokens)
    {
        m_tokens[YX(y, x)] = t;

        if (m_ea2yx.count(t.ea) == 0)
        {
            m_ea2yx[t.ea] = YX(y, x);
        }

        if (t.kind == Token::Kind::NEW_LINE)
        {
            ++y;
            x = YX::starting_x;
        }
        else
        {
            x += t.value.size();
        }
    }
}

func_t* Function::get_func_t() const
{
    return m_p_func_t;
}

std::string Function::getName() const
{
    VERIFY(nullptr != m_p_func_t);
    if (nullptr == m_p_func_t)
        return "";

    qstring qFncName;
    get_func_name(&qFncName, m_p_func_t->start_ea);
    return qFncName.c_str();
}

ea_t Function::getStart() const
{
    VERIFY(nullptr != m_p_func_t);
    if (nullptr == m_p_func_t)
    {
        return BADADDR;
    }

    return m_p_func_t->start_ea;
}

ea_t Function::getEnd() const
{
    VERIFY(nullptr != m_p_func_t);
    if (nullptr == m_p_func_t)
    {
        return BADADDR;
    }

    return m_p_func_t->end_ea;
}

const Token* Function::getToken(YX yx) const
{
    auto it = m_tokens.find(adjust_yx(yx));
    return it == m_tokens.end() ? nullptr : &it->second;
}

const std::map<YX, Token>& Function::getTokens() const
{
    return m_tokens;
}

YX Function::min_yx() const
{
    return m_tokens.empty() ? YX::starting_yx : m_tokens.begin()->first;
}

YX Function::max_yx() const
{
    return m_tokens.empty() ? YX::starting_yx : m_tokens.rbegin()->first;
}

YX Function::prev_yx(YX yx) const
{
    auto it = m_tokens.find(adjust_yx(yx));
    if (it == m_tokens.end() || it == m_tokens.begin())
    {
        return yx;
    }
    --it;
    return it->first;
}

YX Function::next_yx(YX yx) const
{
    auto it = m_tokens.find(adjust_yx(yx));
    auto nit = it;
    ++nit;
    if (it == m_tokens.end() || nit == m_tokens.end())
    {
        return yx;
    }
    return nit->first;
}

YX Function::adjust_yx(YX yx) const
{
    if (m_tokens.empty() || m_tokens.count(yx))
    {
        return yx;
    }
    if (yx <= min_yx())
    {
        return min_yx();
    }
    if (yx >= max_yx())
    {
        return max_yx();
    }

    auto it = m_tokens.upper_bound(yx);
    --it;
    return it->first;
}

std::string Function::line_yx(YX yx) const
{
    std::string line;

    auto it = m_tokens.find(adjust_yx(yx));
    while (it != m_tokens.end()
            && it->first.y == yx.y
            && it->second.kind != Token::Kind::NEW_LINE)
    {
        line += std::string(SCOLOR_ON)
                + it->second.getColorTag()
                + it->second.value
                + SCOLOR_OFF
                + it->second.getColorTag();
        ++it;
    }

    return line;
}

ea_t Function::yx_2_ea(YX yx) const
{
    auto it = m_tokens.find(adjust_yx(yx));
    if (it == m_tokens.end())
    {
        return BADADDR;
    }
    return it->second.ea;
}

std::set<ea_t> Function::yx_2_eas(YX yx) const
{
    std::set<ea_t> ret;
    auto it = m_tokens.find(YX(yx.y, 0));
    while (it != m_tokens.end() && it->first.y == yx.y)
    {
        ret.insert(it->second.ea);
        ++it;
    }
    return ret;
}

YX Function::ea_2_yx(ea_t ea) const
{
    if (m_ea2yx.empty())
    {
        return YX::starting_yx;
    }
    if (ea < m_ea2yx.begin()->first || m_ea2yx.rbegin()->first < ea)
    {
        return YX::starting_yx;
    }
    if (ea == m_ea2yx.rbegin()->first)
    {
        return max_yx();
    }

    auto it = m_ea2yx.upper_bound(ea);
    --it;
    return it->second;
}

bool Function::ea_inside(ea_t ea) const
{
    return getStart() <= ea && ea < getEnd();
}

std::vector<std::pair<std::string, ea_t>> Function::toLines() const
{
    std::vector<std::pair<std::string, ea_t>> lines;

    ea_t addr = BADADDR;
    std::string line;
    for (auto& p : m_tokens)
    {
        if (addr == BADADDR)
        {
            addr = p.second.ea;
        }

        auto& t = p.second;
        if (t.kind == Token::Kind::NEW_LINE)
        {
            lines.emplace_back(std::make_pair(line, addr));
            line.clear();
            addr = BADADDR;
        }
        else
        {
            line += t.value;
        }
    }

    return lines;
}

std::string Function::toString() const
{
    std::stringstream ss;
    ss << *this;
    return ss.str();
}

std::ostream& operator<<(std::ostream& os, const Function& f)
{
    os << f.getName() << "<" << std::hex << f.getStart() << "," << f.getEnd() << ")";
    return os;
}
