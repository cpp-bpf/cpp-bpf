/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef CPPBPF_USER_RINGBUF_HPP
#define CPPBPF_USER_RINGBUF_HPP

#include <bpf/libbpf.h>
#include <cerrno>
#include <cstring>
#include <new>
#include <type_traits>
#include <utility>

namespace cppbpf::user {

/*
 * Reads records from one or more ring buffer maps, each with a callback
 * that takes the record type written by the BPF program:
 *
 *   cppbpf::user::ring_reader reader;
 *   reader.add<event>(obj->maps.events, [&](const event &e) { ... });
 *   reader.poll(100);
 *
 * A callback may return void, or an int as in libbpf: a negative value
 * stops polling and is returned from poll() or consume(). Callbacks must
 * not throw, as they are called from libbpf. Records shorter than the type
 * are skipped. No operation throws; errors are negative errno values.
 */
class ring_reader {
public:
	ring_reader() = default;
	ring_reader(const ring_reader &) = delete;
	ring_reader &operator=(const ring_reader &) = delete;

	ring_reader(ring_reader &&other) noexcept
	{
		swap(other);
	}

	ring_reader &operator=(ring_reader &&other) noexcept
	{
		ring_reader tmp(std::move(other));
		swap(tmp);
		return *this;
	}

	~ring_reader()
	{
		ring_buffer__free(rb_);
		while (callbacks_) {
			callback_base *next = callbacks_->next;
			delete callbacks_;
			callbacks_ = next;
		}
	}

	template <class T, class F>
	int add(struct bpf_map *map, F &&f)
	{
		static_assert(std::is_trivially_copyable_v<T>,
			      "ring buffer records must be trivially copyable");
		using cb_type = callback<T, std::decay_t<F>>;

		int fd = bpf_map__fd(map);
		if (fd < 0)
			return fd;
		auto *cb = new (std::nothrow) cb_type(std::forward<F>(f));
		if (!cb)
			return -ENOMEM;

		int err = 0;
		if (!rb_) {
			rb_ = ring_buffer__new(fd, &cb_type::handle, cb,
					       nullptr);
			if (!rb_)
				err = -errno;
		} else {
			err = ring_buffer__add(rb_, fd, &cb_type::handle, cb);
		}
		if (err) {
			delete cb;
			return err;
		}
		cb->next = callbacks_;
		callbacks_ = cb;
		return 0;
	}

	/* Wait up to timeout_ms for records; returns the number consumed. */
	int poll(int timeout_ms)
	{
		return rb_ ? ring_buffer__poll(rb_, timeout_ms) : -EINVAL;
	}

	/* Consume the available records without waiting. */
	int consume()
	{
		return rb_ ? ring_buffer__consume(rb_) : -EINVAL;
	}

	void swap(ring_reader &other) noexcept
	{
		std::swap(rb_, other.rb_);
		std::swap(callbacks_, other.callbacks_);
	}

private:
	struct callback_base {
		virtual ~callback_base() = default;
		callback_base *next = nullptr;
	};

	template <class T, class F>
	struct callback : callback_base {
		template <class G>
		explicit callback(G &&g) : f_(std::forward<G>(g))
		{
		}

		static int handle(void *ctx, void *data, size_t size) noexcept
		{
			if (size < sizeof(T))
				return 0;
			unsigned char buf[sizeof(T)];
			std::memcpy(buf, data, sizeof(T));
			const T rec = __builtin_bit_cast(T, buf);
			auto *self = static_cast<callback *>(ctx);
			if constexpr (std::is_void_v<std::invoke_result_t<
					      F &, const T &>>) {
				self->f_(rec);
				return 0;
			} else {
				return self->f_(rec);
			}
		}

		F f_;
	};

	struct ring_buffer *rb_ = nullptr;
	/* Owned; libbpf holds pointers to them as callback contexts. */
	callback_base *callbacks_ = nullptr;
};

} /* namespace cppbpf::user */

#endif /* CPPBPF_USER_RINGBUF_HPP */
