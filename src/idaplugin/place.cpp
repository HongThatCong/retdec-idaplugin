#include <sstream>

#include "retdec.h"
#include "place.h"

static const idaplace_t _idaplace;
static const retdec_place_t _template(nullptr, YX());

void idaapi retdec_place_t::print(qstring* out_buf, void* ud) const
{
    qstring ea_str;
    ea2str(&ea_str, toea());

    std::string str = std::string(ea_str.c_str()) + " @ " + std::to_string(y()) + ":" + std::to_string(x());
    *out_buf = str.c_str();
}

uval_t idaapi retdec_place_t::touval(void* ud) const
{
    return y();
}

place_t* idaapi retdec_place_t::clone(void) const
{
    return new retdec_place_t(*this);
}

void idaapi retdec_place_t::copyfrom(const place_t* from)
{
    auto* p = static_cast<const retdec_place_t*>(from);
    VERIFY(nullptr != p);
    if (nullptr == p)
    {
        return;
    }

    lnnum = p->lnnum;
    m_pFunction = p->m_pFunction;
    _yx = p->_yx;
}

place_t* idaapi retdec_place_t::makeplace(void* ud, uval_t y, int lnnum) const
{
    auto* p = new retdec_place_t(m_pFunction, YX(y, 0));
    VERIFY(nullptr != p);
    if (nullptr == p)
    {
        return nullptr;
    }

    p->lnnum = lnnum;
    return p;
}

int idaapi retdec_place_t::compare(const place_t* t2) const
{
    return compare2(t2, nullptr);
}

int idaapi retdec_place_t::compare2(const place_t* t2, void *ud) const
{
    auto* p = static_cast<const retdec_place_t*>(t2);
    VERIFY(nullptr != p);
    if (nullptr == p)
    {
        return 0;
    }

    VERIFY(nullptr != m_pFunction);
    if (nullptr == m_pFunction)
    {
        return 0;
    }

    VERIFY(nullptr != p->m_pFunction);
    if (nullptr == p->m_pFunction)
    {
        return 0;
    }

    if (m_pFunction == p->m_pFunction)
    {
        if (yx() < p->yx())
            return -1;
        else if (yx() > p->yx())
            return 1;
        else
            return 0;
    }
    // I'm not sure if this can happen (i.e. places from different functions
    // are compared), but better safe than sorry.
    else if (m_pFunction->getStart() < p->m_pFunction->getStart())
    {
        return -1;
    }
    else
    {
        return 1;
    }
}

void idaapi retdec_place_t::adjust(void* ud)
{
    // No idea if some handling is needed here.
    // It seems to work OK just like this.
    // The following is not working:
    //     _yx = m_pFunction->adjust_yx(_yx);
    // Sometimes it generates some extra empty lines.
    _yx.x = 0;
}

bool idaapi retdec_place_t::prev(void* ud)
{
    VERIFY(nullptr != m_pFunction);
    if (nullptr == m_pFunction)
    {
        return false;
    }

    auto pyx = m_pFunction->prev_yx(yx());
    if (yx() <= m_pFunction->min_yx() || pyx == yx())
    {
        return false;
    }

    _yx = pyx;
    return true;
}

bool idaapi retdec_place_t::next(void* ud)
{
    VERIFY(nullptr != m_pFunction);
    if (nullptr == m_pFunction)
    {
        return false;
    }

    auto nyx = m_pFunction->next_yx(yx());
    if (yx() >= m_pFunction->max_yx() || nyx == yx())
    {
        return false;
    }

    _yx = nyx;
    return true;
}

bool idaapi retdec_place_t::beginning(void* ud) const
{
    VERIFY(nullptr != m_pFunction);
    if (nullptr == m_pFunction)
    {
        return false;
    }

    return yx() == m_pFunction->min_yx();
}

bool idaapi retdec_place_t::ending(void* ud) const
{
    VERIFY(nullptr != m_pFunction);
    if (nullptr == m_pFunction)
    {
        return false;
    }

    return yx() == m_pFunction->max_yx();
}

int idaapi retdec_place_t::generate(qstrvec_t* out,
                                    int* out_deflnnum,
                                    color_t* out_pfx_color,
                                    bgcolor_t* out_bgcolor,
                                    void* ud,
                                    int maxsize) const
{
    VERIFY(nullptr != m_pFunction);
    if (nullptr == m_pFunction)
    {
        return 0;
    }

    if (maxsize <= 0)
    {
        return 0;
    }

    if (x() != 0)
    {
        return 0;
    }

    *out_deflnnum = 0;

    std::string str = m_pFunction->line_yx(yx());
    out->push_back(str.c_str());

    return 1;
}

// All members must be serialized and deserialized.
// This is apparently used when places are moved around.
// When I didn't serialize m_pFunction pointer, I lost the info about it when
// place was set to lochist_entry_t.
// However, this is also used when saving/loading IDB, and so if we store and
// than load function pointer, we are in trouble. Instead we serialize functions
// as their addresses and use decompiler to get an actual function pointer.
void idaapi retdec_place_t::serialize(bytevec_t* out) const
{
    place_t__serialize(this, out);
#if IDA_SDK_VERSION > 720
    out->pack_ea(m_pFunction->getStart());
    out->pack_ea(y());
    out->pack_ea(x());
#else
    uchar packed[10] = { 0 };

    size_t len = ::pack_ea(packed, packed + sizeof(packed), m_pFunction->getStart()) - packed;
    out->append(packed, len);

    memset(packed, 0, sizeof(packed));
    len = ::pack_ea(packed, packed + sizeof(packed), y()) - packed;
    out->append(packed, len);

    memset(packed, 0, sizeof(packed));
    len = ::pack_ea(packed, packed + sizeof(packed), x()) - packed;
    out->append(packed, len);
#endif
}

bool idaapi retdec_place_t::deserialize(const uchar** pptr,const uchar* end)
{
    if (!place_t__deserialize(this, pptr, end) || *pptr >= end)
    {
        return false;
    }
    auto fa = unpack_ea(pptr, end);
    m_pFunction = RetDec::selectiveDecompilation(fa, false);
    auto y = unpack_ea(pptr, end);
    auto x = unpack_ea(pptr, end);
    _yx = YX(y, x);
    return true;
}

int idaapi retdec_place_t::id() const
{
    return retdec_place_t::ID;
}

const char* idaapi retdec_place_t::name() const
{
    return retdec_place_t::_name;
}

ea_t idaapi retdec_place_t::toea() const
{
    VERIFY(nullptr != m_pFunction);
    if (nullptr == m_pFunction)
    {
        return BADADDR;
    }

    return m_pFunction->yx_2_ea(yx());
}

bool idaapi retdec_place_t::rebase(const segm_move_infos_t&)
{
    // nothing
    return false;
}

place_t* idaapi retdec_place_t::enter(uint32*) const
{
    // nothing
    return nullptr;
}

void idaapi retdec_place_t::leave(uint32) const
{
    // nothing
}

int retdec_place_t::ID = -1;

retdec_place_t::retdec_place_t(Function* fnc, YX yx) : m_pFunction(fnc), _yx(yx)
{
    lnnum = 0;
}

void retdec_place_t::registerPlace(const plugin_t& PLUGIN)
{
    // HTC - temporary pass the inter 40662 bug of IDA
    int flags = 0;  // for IDA 7.3, 7.4
    ida_version_t ida_ver = getIDAVersion();
    if (ida_ver <= ida_72)
        flags = PCF_EA_CAPABLE;
    else if (ida_ver >= ida_75)
        flags = PCF_EA_CAPABLE | PCF_MAKEPLACE_ALLOCATES;

    retdec_place_t::ID = register_place_class(&_template, flags, &PLUGIN);

    /// Register a converter, that will be used for the following reasons:
    /// - determine what view can be synchronized with what other view
    /// - when views are synchronized, convert the location from one view,
    ///   into an appropriate location in the other view
    /// - if one of p1 or p2 is "idaplace_t", and the other is PCF_EA_CAPABLE,
    ///   then the converter will also be called when the user wants to jump to
    ///   an address (e.g., by pressing "g"). In that case, from's place_t's lnnum
    ///   will be set to -1 (i.e., can be used to descriminate between proper
    ///   synchronizations, and jump to's if needed.)
    ///
    /// Note: the converter can be used to convert in both directions, and can be
    /// called with its 'from' being of the class of 'p1', or 'p2'.
    /// If you want your converter to work in only one direction (e.g., from
    /// 'my_dictionary_place_t' -> 'my_definition_place_t'), you can have it
    /// return false when it is called with a lochist_entry_t's whose place is
    /// of type 'my_definition_place_t'.
    ///
    /// Note: Whenever one of the 'p1' or 'p2' places is unregistered,
    /// corresponding converters will be automatically unregistered as well.
    register_loc_converter(_template.name(), _idaplace.name(), place_converter);
}

YX retdec_place_t::yx() const
{
    return _yx;
}

std::size_t retdec_place_t::y() const
{
    return yx().y;
}

std::size_t retdec_place_t::x() const
{
    return yx().x;
}

const Token* retdec_place_t::token() const
{
    VERIFY(nullptr != m_pFunction);
    if (nullptr == m_pFunction)
    {
        return false;
    }

    return m_pFunction->getToken(yx());
}

Function* retdec_place_t::getFunction() const
{
    return m_pFunction;
}

std::string retdec_place_t::toString() const
{
    std::stringstream ss;
    ss << *this;
    return ss.str();
}

std::ostream& operator<<(std::ostream& os, const retdec_place_t& p)
{
    os << *p.getFunction() << p.yx();
    return os;
}

bool idaapi place_converter(lochist_entry_t* dst, const lochist_entry_t& src, TWidget* view)
{
    VERIFY(nullptr != dst);
    VERIFY(nullptr != view);
    if (nullptr == dst || nullptr == view)
    {
        return false;
    }

    auto *place = src.place();
    VERIFY(nullptr != place);
    if (nullptr == place)
    {
        return false;
    }

    // idaplace_t -> retdec_place_t
    if (place->name() == std::string(_idaplace.name()))
    {
        auto idaEa = place->toea();

        auto* cur = dynamic_cast<retdec_place_t*>(get_custom_viewer_place(view,
                                                                          false,        // mouse
                                                                          nullptr,      // x
                                                                          nullptr));    // y
        VERIFY(nullptr != cur);
        if (cur == nullptr)
        {
            return false;
        }

        auto *p_curFnc = cur->getFunction();
        VERIFY(nullptr != p_curFnc);
        if (nullptr == p_curFnc)
        {
            return false;
        }

        if (p_curFnc->ea_inside(idaEa))
        {
            retdec_place_t p(p_curFnc, p_curFnc->ea_2_yx(idaEa));
            dst->set_place(p);
            // Set both x and y, see renderer_info_t comment in demo.cpp.
            dst->renderer_info().pos.cy = p.y();
            dst->renderer_info().pos.cx = p.x();
        }
        else
        {
            Function* fnc =  RetDec::selectiveDecompilation(idaEa, false);
            VERIFY(nullptr != fnc);
            if (fnc)
            {
                retdec_place_t cur(fnc, fnc->ea_2_yx(idaEa));
                dst->set_place(cur);

                // Set both x and y, see renderer_info_t comment in demo.cpp.
                dst->renderer_info().pos.cy = cur.y();
                dst->renderer_info().pos.cx = cur.x();
            }
            else
            {
                return false;
            }
        }

        return true;
    }
    // retdec_place_t -> idaplace_t
    else if (src.place()->name() == std::string(_template.name()))
    {
        auto* demoPlc = static_cast<const retdec_place_t*>(src.place());
        idaplace_t p(demoPlc->toea(), 0);
        dst->set_place(p);
        return true;
    }
    // should not happen
    else
    {
        return false;
    }
}
