/* 
 * Copyright (C) 2010 Julien Pommier
 * Copyright (C) 2020 Dimitri Diakopoulos
 *
 * This software is provided 'as-is', without any express or implied
 * warranty.  In no event will the authors be held liable for any damages
 * arising from the use of this software.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to the following restrictions:
 *
 * 1. The origin of this software must not be misrepresented; you must not
 *    claim that you wrote the original software. If you use this software
 *    in a product, an acknowledgment in the product documentation would be
 *    appreciated but is not required.
 * 2. Altered source versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.
 * 3. This notice may not be removed or altered from any source distribution.
 *
 */

#pragma once

#ifndef tinyosc_hpp
#define tinyosc_hpp

#include <cassert>
#include <cstring>
#include <list>
#include <stdint.h>
#include <string>
#include <vector>
#include <numeric>
#include <limits>

#ifdef min
    #undef min
#endif
#ifdef max
    #undef max
#endif

#pragma warning(push)
#pragma warning(disable : 4996)  // disable _CRT_SECURE_NO_WARNINGS on Windows

namespace tinyosc
{
    // clang-format off
    #if defined(TINYOSC_DEBUG)
        #define OSC_SET_ERROR(errcode) do { if (!the_error) { the_error = errcode; std::cerr << "set " #errcode << " at line " << __LINE__ << "\n"; } } while (0)
    #else
        #define OSC_SET_ERROR(errcode) do { if (!the_error) the_error = errcode; } while (0)
    #endif

    enum class osc_type_tag
    {
        TYPE_TAG_TRUE    = 'T',
        TYPE_TAG_FALSE   = 'F',
        TYPE_TAG_INT32   = 'i',
        TYPE_TAG_INT64   = 'h',
        TYPE_TAG_FLOAT   = 'f',
        TYPE_TAG_DOUBLE  = 'd',
        TYPE_TAG_STRING  = 's',
        TYPE_TAG_BLOB    = 'b',
        TYPE_TAG_INVALID = '/'
    };
    // clang-format on

    class time_tag
    {
        uint64_t v{1};  // the highest 32-bit are seconds, the lowest are fraction of a second.
    public:
        time_tag() = default;
        explicit time_tag(uint64_t w) : v(w) {}
        operator uint64_t() const { return v; }
        static time_tag immediate() { return time_tag(1); }
    };

    namespace detail
    {
        // round to the next multiple of 4, works for size_t and pointer arguments
        template <typename T>
        inline T ceil4(T p)
        {
            return (T)((size_t(p) + 3) & (~size_t(3)));
        }

        // check that a memory area is zero padded until the next address which is a multiple of 4
        inline bool check_zero_padding(const char * p)
        {
            const char * q = ceil4(p);
            for (; p < q; ++p)
                if (*p != 0) { return false; }
            return true;
        }

        template <typename POD>
        union pod_as_bytes
        {
            char bytes[sizeof(POD)];
            POD value;
        };

        // read unaligned bytes into a POD type, assuming the bytes are a little endian representation
        template <typename POD>
        POD bytes_to_pod(const char * bytes)
        {
            pod_as_bytes<POD> p;
            for (size_t i = 0; i < sizeof(POD); ++i)
            {
                p.bytes[i] = bytes[sizeof(POD) - i - 1];
            }
            return p.value;
        }

        // Store a POD type into an unaligned bytes array, using little endian representation
        template <typename POD>
        void pod_to_bytes(const POD value, char * bytes)
        {
            pod_as_bytes<POD> p;
            p.value = value;
            for (size_t i = 0; i < sizeof(POD); ++i)
            {
                bytes[i] = p.bytes[sizeof(POD) - i - 1];
            }
        }

        // Handles dynamic storage with correct alignment to 4 bytes
        struct net_storage
        {
            std::vector<char> buffer;
            net_storage() { buffer.reserve(256); }

            char * begin() { return buffer.size() ? &buffer.front() : 0; }
            char * end() { return begin() + size(); }

            const char * begin() const { return buffer.size() ? &buffer.front() : 0; }
            const char * end() const { return begin() + size(); }

            void assign(const char * beg, const char * end) { buffer.assign(beg, end); }
            void clear() { buffer.resize(0); }

            size_t size() const { return buffer.size(); }

            char * data(size_t sz)
            {
                assert((buffer.size() & 3) == 0);
                if (buffer.size() + sz > buffer.capacity()) { buffer.reserve((buffer.size() + sz) * 2); }
                size_t sz4 = ceil4(sz);
                size_t pos = buffer.size();
                buffer.resize(pos + sz4);  // resize will fill with zeros, so the zero padding is OK
                return &(buffer[pos]);
            }
        };

        // See the OSC spec for the precise pattern matching rules
        // http://opensoundcontrol.org/spec-1_0
        inline const char * pattern_match_impl(const char * pattern, const char * path)
        {
            while (*pattern)
            {
                const char * p = pattern;
                if (*p == '?' && *path)
                {
                    ++p;
                    ++path;
                }
                else if (*p == '[' && *path)
                {
                    // bracketted range, e.g. [a-zABC]
                    ++p;
                    bool reverse = false;
                    if (*p == '!')
                    {
                        reverse = true;
                        ++p;
                    }
                    bool match_complete = reverse;
                    for (; *p && *p != ']'; ++p)
                    {
                        char c0 = *p, c1 = c0;
                        if (p[1] == '-' && p[2] && p[2] != ']')
                        {
                            p += 2;
                            c1 = *p;
                        }
                        if (*path >= c0 && *path <= c1) { match_complete = !reverse; }
                    }
                    if (!match_complete || *p != ']') return pattern;
                    ++p;
                    ++path;
                }
                else if (*p == '*')
                {
                    // wildcard '*'
                    while (*p == '*') ++p;
                    const char * best = 0;
                    while (true)
                    {
                        const char * ret = pattern_match_impl(p, path);
                        if (ret && ret > best) best = ret;
                        if (*path == 0 || *path == '/')
                            break;
                        else
                            ++path;
                    }
                    return best;
                }
                else if (*p == '/' && *(p + 1) == '/')
                {
                    // the super-wildcard '//'
                    while (*(p + 1) == '/') ++p;
                    const char * best = 0;
                    while (true)
                    {
                        const char * ret = pattern_match_impl(p, path);
                        if (ret && ret > best) best = ret;
                        if (*path == 0) break;
                        if (*path == 0 || (path = strchr(path + 1, '/')) == 0) break;
                    }
                    return best;
                }
                else if (*p == '{')
                {
                    // braced list {foo,bar,baz}
                    const char *end = strchr(p, '}'), *q;
                    if (!end) return 0;  // syntax error in brace list..
                    bool match_complete = false;
                    do
                    {
                        ++p;
                        q = strchr(p, ',');
                        if (q == 0 || q > end) q = end;
                        if (strncmp(p, path, q - p) == 0)
                        {
                            path += (q - p);
                            p              = end + 1;
                            match_complete = true;
                        }
                        else
                            p = q;
                    } while (q != end && !match_complete);
                    if (!match_complete) return pattern;
                }
                else if (*p == *path)
                {
                    ++p;
                    ++path;
                }
                else
                {
                    break;
                }
                pattern = p;
            }
            return (*path == 0 ? pattern : 0);
        }

        // check if the path matches the beginning of pattern
        inline bool pattern_match_partial(const std::string & pattern, const std::string & test)
        {
            const char * q = pattern_match_impl(pattern.c_str(), test.c_str());
            return q != 0;
        }

        // check if the path matches the supplied path pattern , according to the OSC spec pattern
        // rules ('*' and '//' wildcards, '{}' alternatives, brackets etc)
        inline bool pattern_match_complete(const std::string & pattern, const std::string & test)
        {
            const char * q = pattern_match_impl(pattern.c_str(), test.c_str());
            return q && *q == 0;
        }

    }  // namespace detail

    typedef enum
    {
        no_problem = 0,
        malformed_address,
        malformed_type_tags,
        malformed_arguments,
        unhandled_type_tags,
        type_mismatch,
        not_enough_args,
        pattern_mismatch,
        invalid_bundle,
        invalid_packet_size,
        bundle_required_for_multi_messages
    } osc_error;

    ///////////////////////
    //    osc_message    //
    ///////////////////////

    class osc_message
    {
        time_tag tt;
        std::string address;
        std::string type_tags;
        std::vector<std::pair<size_t, size_t>> arguments;  // array of pairs (pos,size), pos being an index into the 'storage' array.
        detail::net_storage storage;                       // the arguments data is stored here
        osc_error the_error;

    public:
        // argument_parser is used for popping arguments from a osc_message, holds a pointer to
        // the original osc_message, and maintains a local error code
        class argument_parser
        {
            const osc_message * msg;
            osc_error the_error;
            size_t arg_idx;  // arg index of the next arg that will be popped out.

        public:
            argument_parser(const osc_message & m, osc_error e = no_problem) : msg(&m), the_error(msg->get_error()), arg_idx(0)
            {
                if (e != no_problem && the_error == no_problem)
                {
                    the_error = e;
                }
            }

            argument_parser(const argument_parser & other) : msg(other.msg), the_error(other.the_error), arg_idx(other.arg_idx) {}

            bool is_bool() { return get_current_type_tag() == osc_type_tag::TYPE_TAG_TRUE || get_current_type_tag() == osc_type_tag::TYPE_TAG_FALSE; }
            bool is_int32() { return get_current_type_tag() == osc_type_tag::TYPE_TAG_INT32; }
            bool is_int64() { return get_current_type_tag() == osc_type_tag::TYPE_TAG_INT64; }
            bool is_float() { return get_current_type_tag() == osc_type_tag::TYPE_TAG_FLOAT; }
            bool is_double() { return get_current_type_tag() == osc_type_tag::TYPE_TAG_DOUBLE; }
            bool is_string() { return get_current_type_tag() == osc_type_tag::TYPE_TAG_STRING; }
            bool is_blob() { return get_current_type_tag() == osc_type_tag::TYPE_TAG_BLOB; }

            size_t args_remaining() const { return msg->arguments.size() - arg_idx; }

            bool check_error() const { return the_error == no_problem; }
            operator bool() const { return check_error(); }  // implicit bool

            // call this at the end of the popXXX() chain to make sure everything is ok and all arguments have been popped
            bool check_no_more_args() const { return the_error == no_problem && args_remaining() == 0; }

            osc_error get_error() const { return the_error; }

            argument_parser & pop_int32(int32_t & i) { return pop_pod<int32_t>(osc_type_tag::TYPE_TAG_INT32, i); }
            argument_parser & pop_int64(int64_t & i) { return pop_pod<int64_t>(osc_type_tag::TYPE_TAG_INT64, i); }
            argument_parser & pop_float(float & f) { return pop_pod<float>(osc_type_tag::TYPE_TAG_FLOAT, f); }
            argument_parser & pop_double(double & d) { return pop_pod<double>(osc_type_tag::TYPE_TAG_DOUBLE, d); }

            // retrieve a string argument (no check performed on its content, so it may contain any byte value except 0)
            argument_parser & pop_string(std::string & s)
            {
                if (validate(osc_type_tag::TYPE_TAG_STRING))
                {
                    s = arg_beg(arg_idx++);
                }
                return *this;
            }

            argument_parser & pop_blob(std::vector<char> & b)
            {
                if (validate(osc_type_tag::TYPE_TAG_BLOB))
                {
                    b.assign(arg_beg(arg_idx) + 4, arg_end(arg_idx));
                    ++arg_idx;
                }
                return *this;
            }

            argument_parser & pop_bool(bool & b)
            {
                b = false;
                if (arg_idx >= msg->arguments.size())
                    OSC_SET_ERROR(not_enough_args);
                else if (get_current_type_tag() == osc_type_tag::TYPE_TAG_TRUE)
                    b = true;
                else if (get_current_type_tag() == osc_type_tag::TYPE_TAG_FALSE)
                    b = false;
                else
                    OSC_SET_ERROR(type_mismatch);
                ++arg_idx;
                return *this;
            }

            // skip whatever comes next
            argument_parser & pop_any()
            {
                if (arg_idx >= msg->arguments.size())
                    OSC_SET_ERROR(not_enough_args);
                else
                    ++arg_idx;
                return *this;
            }

        private:
            const char * arg_beg(const size_t idx)
            {
                if (the_error || idx >= msg->arguments.size())
                    return 0;
                else
                    return msg->storage.begin() + msg->arguments[idx].first;
            }

            const char * arg_end(const size_t idx)
            {
                if (the_error || idx >= msg->arguments.size())
                    return 0;
                else
                    return msg->storage.begin() + msg->arguments[idx].first + msg->arguments[idx].second;
            }

            osc_type_tag get_current_type_tag()
            {
                if (!the_error && arg_idx < msg->type_tags.size())
                    return static_cast<osc_type_tag>(msg->type_tags[arg_idx]);
                else
                    OSC_SET_ERROR(not_enough_args);
                return osc_type_tag::TYPE_TAG_INVALID;
            }

            template <typename POD>
            argument_parser & pop_pod(osc_type_tag tag, POD & v)
            {
                if (validate(tag))
                {
                    v = detail::bytes_to_pod<POD>(arg_beg(arg_idx));
                    ++arg_idx;
                }
                else
                {
                    v = POD(0);
                }
                return *this;
            }

            // Validate a few error conditions before popping an argument from the message
            bool validate(const osc_type_tag tag)
            {
                if (arg_idx >= msg->arguments.size())
                    OSC_SET_ERROR(not_enough_args);
                else if (!the_error && get_current_type_tag() != tag)
                    OSC_SET_ERROR(type_mismatch);
                return the_error == no_problem;
            }
        };

        osc_message() { clear(); }
        osc_message(const std::string & s, time_tag tt = time_tag::immediate()) : tt(tt), address(s), the_error(no_problem) {}

        osc_message(const void * ptr, size_t sz, time_tag tt = time_tag::immediate())
        {
            initialize_from_raw_bytes(ptr, sz);
            this->tt = tt;
        }

        bool check_error() const { return the_error == no_problem; }
        osc_error get_error() const { return the_error; }

        std::string get_type_tags() const { return type_tags; }
        time_tag get_time_tag() const { return tt; }

        // retrieve the address pattern. If you want to follow to the whole OSC spec, you
        // have to handle its matching rules for address specifications -- this file does
        // not provide this functionality
        std::string get_address_pattern() const { return address; }

        // clear the message and start a new message with the supplied address and time_tag.
        osc_message & initialize(const std::string & the_address, const time_tag the_timetag = time_tag::immediate())
        {
            clear();
            address = the_address;
            tt      = the_timetag;
            if (address.empty() || address[0] != '/') OSC_SET_ERROR(malformed_address);
            return *this;
        }

        // Start a matching test. The typical use-case is to follow this by
        // a sequence of calls to popXXX() and a final call to
        // check_no_more_args() which will allow to check that everything went
        // fine. For example:
        // > if (msg.match_complete("/foo").pop_int32(i).check_no_more_args()) { blah(i); }
        // > else if (msg.match_complete("/bar").pop_string(s).pop_int32(i).check_no_more_args()) { plop(s,i); }
        // > else cerr << "unhandled message: " << msg << "\n";
        argument_parser match_complete(const std::string & test) const
        {
            return argument_parser(*this, detail::pattern_match_complete(address.c_str(), test.c_str()) ? no_problem : pattern_mismatch);
        }

        // Return true if the 'test' path matched by the first characters of get_address_pattern().
        // For ex. ("/foo/bar").match_partial("/foo/") is true
        argument_parser match_partial(const std::string & test) const
        {
            return argument_parser(*this, detail::pattern_match_partial(address.c_str(), test.c_str()) ? no_problem : pattern_mismatch);
        }

        argument_parser arg()
        {
            return argument_parser(*this, no_problem);
        }

        // below are all the functions that serve when *writing* a message
        osc_message & push_bool(bool b)
        {
            type_tags.push_back(b ? static_cast<char>(osc_type_tag::TYPE_TAG_TRUE) : static_cast<char>(osc_type_tag::TYPE_TAG_FALSE));
            arguments.push_back(std::make_pair(storage.size(), storage.size()));
            return *this;
        }

        osc_message & push_int32(int32_t i) { return push_pod_data(osc_type_tag::TYPE_TAG_INT32, i); }
        osc_message & push_int64(int64_t h) { return push_pod_data(osc_type_tag::TYPE_TAG_INT64, h); }
        osc_message & push_float(float f) { return push_pod_data(osc_type_tag::TYPE_TAG_FLOAT, f); }
        osc_message & push_double(double d) { return push_pod_data(osc_type_tag::TYPE_TAG_DOUBLE, d); }

        osc_message & push_string(const std::string & s)
        {
            assert(s.size() < std::numeric_limits<int32_t>::max());  // insane values are not welcome
            type_tags.push_back(static_cast<char>(osc_type_tag::TYPE_TAG_STRING));
            arguments.push_back(std::make_pair(storage.size(), s.size() + 1));
            std::strcpy(storage.data(s.size() + 1), s.c_str());
            return *this;
        }

        osc_message & push_blob(void * ptr, size_t num_bytes)
        {
            assert(num_bytes < std::numeric_limits<int32_t>::max());  // insane values are not welcome
            type_tags.push_back(static_cast<char>(osc_type_tag::TYPE_TAG_BLOB));
            arguments.push_back(std::make_pair(storage.size(), num_bytes + 4));
            detail::pod_to_bytes<int32_t>((int32_t) num_bytes, storage.data(4));
            if (num_bytes) std::memcpy(storage.data(num_bytes), ptr, num_bytes);
            return *this;
        }

        // reset the message to a clean state
        void clear()
        {
            tt = time_tag::immediate();
            address.clear();
            type_tags.clear();
            storage.clear();
            arguments.clear();
            the_error = no_problem;
        }

        // write the raw message data (used by osc_packet_writer)
        void pack_message(detail::net_storage & s, bool write_size) const
        {
            if (!check_error()) return;
            size_t l_addr = address.size() + 1, l_type = type_tags.size() + 2;
            if (write_size)
            {
                detail::pod_to_bytes<uint32_t>(uint32_t(detail::ceil4(l_addr) + detail::ceil4(l_type) + detail::ceil4(storage.size())), s.data(4));
            }
            std::strcpy(s.data(l_addr), address.c_str());
            std::strcpy(s.data(l_type), ("," + type_tags).c_str());
            if (storage.size())
            {
                std::memcpy(s.data(storage.size()), const_cast<detail::net_storage &>(storage).begin(), storage.size());
            }
        }

        // build the osc message for raw data (the message will keep a copy of that data)
        void initialize_from_raw_bytes(const void * ptr, size_t sz)
        {
            clear();
            storage.assign((const char *) ptr, (const char *) ptr + sz);
            const char * address_beg = storage.begin();
            const char * address_end = (const char *) memchr(address_beg, 0, storage.end() - address_beg);
            if (!address_end || !detail::check_zero_padding(address_end + 1) || address_beg[0] != '/')
            {
                OSC_SET_ERROR(malformed_address);
                return;
            }
            else
            {
                address.assign(address_beg, address_end);
            }

            const char * type_tags_beg = detail::ceil4(address_end + 1);
            const char * type_tags_end = (const char *) memchr(type_tags_beg, 0, storage.end() - type_tags_beg);
            if (!type_tags_end || !detail::check_zero_padding(type_tags_end + 1) || type_tags_beg[0] != ',')
            {
                OSC_SET_ERROR(malformed_type_tags);
                return;
            }
            else
            {
                type_tags.assign(type_tags_beg + 1, type_tags_end);  // we do not copy the initial ','
            }

            const char * arg = detail::ceil4(type_tags_end + 1);
            assert(arg <= storage.end());
            size_t iarg = 0;
            while (check_error() && iarg < type_tags.size())
            {
                assert(arg <= storage.end());
                size_t len = get_argument_size(static_cast<osc_type_tag>(type_tags[iarg]), arg);
                if (check_error()) arguments.push_back(std::make_pair(arg - storage.begin(), len));
                arg += detail::ceil4(len);
                ++iarg;
            }

            if (iarg < type_tags.size() || arg != storage.end())
            {
                OSC_SET_ERROR(malformed_arguments);
            }
        }

    private:
        // get the number of bytes occupied by the argument
        size_t get_argument_size(osc_type_tag type, const char * p)
        {
            if (the_error) return 0;

            size_t sz = 0;
            assert(p >= storage.begin() && p <= storage.end());

            switch (type)
            {
                case osc_type_tag::TYPE_TAG_TRUE:
                case osc_type_tag::TYPE_TAG_FALSE: sz = 0; break;
                case osc_type_tag::TYPE_TAG_INT32:
                case osc_type_tag::TYPE_TAG_FLOAT: sz = 4; break;
                case osc_type_tag::TYPE_TAG_INT64:
                case osc_type_tag::TYPE_TAG_DOUBLE: sz = 8; break;
                case osc_type_tag::TYPE_TAG_STRING:
                {
                    const char * q = (const char *) std::memchr(p, 0, storage.end() - p);
                    if (!q)
                    {
                        OSC_SET_ERROR(malformed_arguments);
                    }
                    else
                    {
                        sz = (q - p) + 1;
                    }
                }
                break;
                case osc_type_tag::TYPE_TAG_BLOB:
                {
                    if (p == storage.end())
                    {
                        OSC_SET_ERROR(malformed_arguments);
                        return 0;
                    }
                    sz = 4 + detail::bytes_to_pod<uint32_t>(p);
                }
                break;
                default:
                {
                    OSC_SET_ERROR(unhandled_type_tags);
                    return 0;
                }
                break;
            }

            // string or blob too large.. or or even blob so large that it did overflow
            if (p + sz > storage.end() || p + sz < p)
            {
                OSC_SET_ERROR(malformed_arguments);
                return 0;
            }

            if (!detail::check_zero_padding(p + sz))
            {
                OSC_SET_ERROR(malformed_arguments);
                return 0;
            }

            return sz;
        }

        template <typename T>
        osc_message & push_pod_data(osc_type_tag tag, T v)
        {
            type_tags.push_back(static_cast<char>(tag));
            arguments.push_back(std::make_pair(storage.size(), sizeof(T)));
            detail::pod_to_bytes(v, storage.data(sizeof(T)));
            return *this;
        }

        friend std::ostream & operator<<(std::ostream & os, const osc_message & msg)
        {
            os << "osc_address: '" << msg.address << "', types: '" << msg.type_tags << "', timetag=" << msg.tt << ", args=[";
            osc_message::argument_parser arg(msg);
            while (arg.args_remaining() && arg.check_error())
            {
                if (arg.is_bool())
                {
                    bool b;
                    arg.pop_bool(b);
                    os << (b ? "True" : "False");
                }
                else if (arg.is_int32())
                {
                    int32_t i;
                    arg.pop_int32(i);
                    os << i;
                }
                else if (arg.is_int64())
                {
                    int64_t h;
                    arg.pop_int64(h);
                    os << h << "ll";
                }
                else if (arg.is_float())
                {
                    float f;
                    arg.pop_float(f);
                    os << f << "f";
                }
                else if (arg.is_double())
                {
                    double d;
                    arg.pop_double(d);
                    os << d;
                }
                else if (arg.is_string())
                {
                    std::string s;
                    arg.pop_string(s);
                    os << "'" << s << "'";
                }
                else if (arg.is_blob())
                {
                    std::vector<char> b;
                    arg.pop_blob(b);
                    os << "Blob " << b.size() << " bytes";
                }
                else
                {
                    assert(0);  // ???
                }
                if (arg.args_remaining()) os << ", ";
            }
            if (!arg.check_error()) { os << " ERROR#" << arg.get_error(); }
            os << "]";
            return os;
        }
    };

    /////////////////////////////
    //    osc_packet_reader    //
    /////////////////////////////

    class osc_packet_reader
    {
        std::list<osc_message> messages;
        std::list<osc_message>::iterator it_messages;
        osc_error the_error{no_problem};

        void parse(const char * beg, const char * end, time_tag tt)
        {
            assert(beg <= end && !the_error);
            assert(((end - beg) % 4) == 0);

            if (beg == end) return;
            if (*beg == '#')
            {
                // bundle
                if (end - beg >= 20 && memcmp(beg, "#bundle\0", 8) == 0)
                {
                    time_tag tt2(detail::bytes_to_pod<uint64_t>(beg + 8));
                    const char * pos = beg + 16;
                    do
                    {
                        uint32_t sz = detail::bytes_to_pod<uint32_t>(pos);
                        pos += 4;
                        if ((sz & 3) != 0 || pos + sz > end || pos + sz < pos)
                        {
                            OSC_SET_ERROR(invalid_bundle);
                        }
                        else
                        {
                            parse(pos, pos + sz, tt2);
                            pos += sz;
                        }
                    } while (!the_error && pos != end);
                }
                else
                {
                    OSC_SET_ERROR(invalid_bundle);
                }
            }
            else
            {
                messages.emplace_back(osc_message(beg, end - beg, tt));

                if (!messages.back().check_error())
                {
                    OSC_SET_ERROR(messages.back().get_error());
                }
            }
        }

    public:
        osc_packet_reader() = default;

        osc_packet_reader(const void * ptr, const size_t size)
        {
            initialize_from_ptr(ptr, size);
        }

        void initialize_from_ptr(const void * ptr, const size_t size)
        {
            the_error = no_problem;
            messages.clear();
            if ((size % 4) == 0)
            {
                parse((const char *) ptr, (const char *) ptr + size, time_tag::immediate());
            }
            else
                OSC_SET_ERROR(invalid_packet_size);
            it_messages = messages.begin();
        }

        // extract the next osc message from the packet. return 0 when all messages have been read, or in case of error.
        osc_message * pop_message()
        {
            if (!the_error && !messages.empty() && it_messages != messages.end())
            {
                return &*it_messages++;
            }
            else
                return 0;
        }

        const bool check_error() const { return the_error == no_problem; }
        const osc_error get_error() const { return the_error; }
    };

    /////////////////////////////
    //    osc_packet_writer    //
    /////////////////////////////

    class osc_packet_writer
    {
        detail::net_storage storage;
        std::vector<size_t> bundles;  // hold the position in the storage array of the beginning marker of each bundle
        osc_error the_error{no_problem};

    public:
        osc_packet_writer() = default;

        osc_packet_writer & reset()
        {
            the_error = no_problem;
            storage.clear();
            bundles.clear();
            return *this;
        }

        // Start a new bundle. If you plan to pack more than one message in the OSC packet, you have to
        // put them in a bundle. Nested bundles inside bundles are also allowed.
        osc_packet_writer & start_bundle(time_tag ts = time_tag::immediate())
        {
            char * p;
            if (bundles.size()) storage.data(4);  // hold the bundle size
            p = storage.data(8);
            std::strcpy(p, "#bundle");
            bundles.push_back(p - storage.begin());
            p = storage.data(8);
            detail::pod_to_bytes<uint64_t>(ts, p);
            return *this;
        }

        // Close the bundle
        osc_packet_writer & end_bundle()
        {
            if (bundles.size())
            {
                if (storage.size() - bundles.back() == 16)
                {
                    detail::pod_to_bytes<uint32_t>(0, storage.data(4));  // the 'empty bundle' case, not very elegant
                }

                if (bundles.size() > 1)
                {
                    // no size stored for the top-level bundle
                    detail::pod_to_bytes<uint32_t>(uint32_t(storage.size() - bundles.back()), storage.begin() + bundles.back() - 4);
                }

                bundles.pop_back();
            }
            else
            {
                OSC_SET_ERROR(invalid_bundle);
            }
            return *this;
        }

        // insert an OSC message into the current bundle / packet.
        osc_packet_writer & add_message(const osc_message & msg)
        {
            if (storage.size() != 0 && bundles.empty())
            {
                OSC_SET_ERROR(bundle_required_for_multi_messages);
            }
            else
            {
                msg.pack_message(storage, bundles.size() > 0);
            }

            if (!msg.check_error())
            {
                OSC_SET_ERROR(msg.get_error());
            }

            return *this;
        }

        // the error flag will be raised if an opened bundle is not closed, or if more than one message is inserted in the packet without a bundle
        const bool check_error() const { return the_error == no_problem; }
        const osc_error get_error() const { return the_error; }

        // return the number of bytes of the osc packet -- will always be a  multiple of 4 -- returns 0 if the construction of the packet has failed.
        const uint32_t size() const { return the_error ? 0 : (uint32_t) storage.size(); }

        // return the bytes of the osc packet (nullptr if the construction of the packet has failed)
        char * data() { return the_error ? nullptr : storage.begin(); }
    };

}  // namespace tinyosc

#pragma warning(pop)

#endif  // end tinyosc_hpp
