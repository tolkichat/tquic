use std::sync::Arc;

use super::*;

// StreamMap unit tests
#[test]
fn streams_new_client() {
    let peer_tp = StreamTransportParams {
        initial_max_streams_bidi: crate::codec::VINT_MAX,
        initial_max_streams_uni: crate::codec::VINT_MAX,
        ..StreamTransportParams::default()
    };
    let mut map = StreamMap::new(false, 50, 50, StreamTransportParams::default());
    map.update_peer_stream_transport_params(peer_tp);

    // client initiated bidirectional streams
    let id = map.stream_bidi_new(0, false);
    assert_eq!(id, Ok(0));
    let id = map.stream_bidi_new(0, false);
    assert_eq!(id, Ok(4));

    assert_eq!(map.stream_set_priority(20, 0, false), Ok(()));
    assert_eq!(map.stream_bidi_new(0, false), Ok(24));
    assert_eq!(
        map.stream_set_priority(crate::codec::VINT_MAX - 3, 0, false),
        Ok(())
    );
    assert_eq!(map.stream_bidi_new(0, false), Err(Error::ProtocolViolation));

    // client initiated unidirectional streams
    let id = map.stream_uni_new(0, false);
    assert_eq!(id, Ok(2));
    let id = map.stream_uni_new(0, false);
    assert_eq!(id, Ok(6));

    assert_eq!(map.stream_set_priority(22, 0, false), Ok(()));
    assert_eq!(map.stream_uni_new(0, false), Ok(26));
    assert_eq!(
        map.stream_set_priority(crate::codec::VINT_MAX - 1, 0, false),
        Ok(())
    );
    assert_eq!(map.stream_uni_new(0, false), Err(Error::ProtocolViolation));
}

#[test]
fn streams_new_server() {
    let peer_tp = StreamTransportParams {
        initial_max_streams_bidi: crate::codec::VINT_MAX,
        initial_max_streams_uni: crate::codec::VINT_MAX,
        ..StreamTransportParams::default()
    };
    let mut map = StreamMap::new(true, 50, 50, StreamTransportParams::default());
    map.update_peer_stream_transport_params(peer_tp);

    // server initiated bidirectional streams
    let id = map.stream_bidi_new(1, false);
    assert_eq!(id, Ok(1));
    let id = map.stream_bidi_new(5, false);
    assert_eq!(id, Ok(5));

    assert_eq!(map.stream_set_priority(21, 0, false), Ok(()));
    assert_eq!(map.stream_bidi_new(0, false), Ok(25));
    assert_eq!(
        map.stream_set_priority(crate::codec::VINT_MAX - 2, 0, false),
        Ok(())
    );
    assert_eq!(map.stream_bidi_new(0, false), Err(Error::ProtocolViolation));

    // server initiated unidirectional streams
    let id = map.stream_uni_new(0, false);
    assert_eq!(id, Ok(3));
    let id = map.stream_uni_new(0, false);
    assert_eq!(id, Ok(7));

    assert_eq!(map.stream_set_priority(23, 0, false), Ok(()));
    assert_eq!(map.stream_uni_new(0, false), Ok(27));
    assert_eq!(
        map.stream_set_priority(crate::codec::VINT_MAX, 0, false),
        Ok(())
    );
    assert_eq!(map.stream_uni_new(0, false), Err(Error::ProtocolViolation));
}

// Test StreamMap::write
#[test]
fn stream_write_invalid_sid() {
    // MUST NOT write on the peer's unidirectional streams.
    let mut map = StreamMap::new(true, 50, 50, StreamTransportParams::default());
    assert_eq!(
        map.stream_write(2, Bytes::new(), false),
        Err(Error::StreamStateError)
    );
}

#[test]
fn stream_write_zero_capacity() {
    let peer_tp = StreamTransportParams {
        initial_max_data: 0,
        initial_max_stream_data_bidi_local: 21,
        initial_max_streams_bidi: 24,
        ..StreamTransportParams::default()
    };

    let mut map = StreamMap::new(false, 50, 50, StreamTransportParams::default());
    map.update_peer_stream_transport_params(peer_tp);

    // When the send capacity is zero, stream_write return Ok(0)
    // only when the send buffer is empty.
    assert_eq!(map.stream_write(0, Bytes::new(), false), Ok(0));
    // When the connection's capacity is exhausted, if the input
    // buffer is not empty, return `Done`.
    assert_eq!(
        map.stream_write(0, Bytes::from_static(b"hello"), false),
        Err(Error::Done)
    );
}

#[test]
fn stream_write_blocked_by_connection_capacity() {
    let peer_tp = StreamTransportParams {
        initial_max_data: 10,
        initial_max_stream_data_bidi_remote: 20,
        initial_max_streams_bidi: 2,
        ..StreamTransportParams::default()
    };

    // 1. Create a client StreamMap
    let mut map = StreamMap::new(false, 50, 50, StreamTransportParams::default());
    map.update_peer_stream_transport_params(peer_tp);

    // 2. Try to write data, but blocked by connection capacity, only partial data is written.
    assert_eq!(
        map.stream_write(0, Bytes::from_static(b"EverythingOverQUIC"), true),
        Ok(10)
    );
    // Stream blocked by connection's send capacity, but the stream is still writable.
    assert_eq!(map.send_capacity.blocked_at, Some(10));
    assert!(map.writable.contains(&0));

    // 3. Update connection capacity, and write more data.
    map.on_max_data_frame_received(20);
    assert_eq!(
        map.stream_write(0, Bytes::from_static(b"OverQUIC"), true),
        Ok(8)
    );
}

#[test]
fn stream_write_basic_logic() {
    let peer_tp = StreamTransportParams {
        initial_max_data: 10,
        initial_max_stream_data_bidi_local: 5,
        initial_max_stream_data_bidi_remote: 5,
        initial_max_stream_data_uni: 5,
        initial_max_streams_bidi: 5,
        initial_max_streams_uni: 5,
    };

    let mut map = StreamMap::new(false, 50, 50, StreamTransportParams::default());
    map.update_peer_stream_transport_params(peer_tp);

    // 1. Send more data than the stream-level flow control limit, the stream is blocked.
    assert_eq!(
        map.stream_write(0, Bytes::from_static(b"Everything"), false),
        Ok(5)
    );
    // init tx_cap is 10, sent 5, so tx_cap is 5 now.
    assert_eq!(map.tx_capacity(), 5);
    assert_eq!(map.tx_data(), 5);

    let stream = map.get(0).unwrap();
    assert!(stream.is_sendable());
    assert!(!stream.is_writable());
    assert_eq!(stream.send.blocked_at(), Some(5));

    // 2. After receiving max_stream_data frame, the stream is writable again.
    map.on_max_stream_data_frame_received(0, 20).unwrap();
    assert_eq!(
        map.stream_write(0, Bytes::from_static(b"thing"), false),
        Ok(5)
    );
    // init tx_cap is 10, sent 10, so tx_cap is 0 now.
    assert_eq!(map.tx_capacity(), 0);
    assert_eq!(map.tx_data(), 10);

    // 3. Send more data than the connection-level flow control limit, the stream is blocked.
    assert_eq!(
        map.stream_write(0, Bytes::from_static(b"OverQUIC"), true),
        Err(Error::Done)
    );

    // 4. After receiving max_data frame, the stream is writable again.
    map.on_max_data_frame_received(30);
    assert_eq!(
        map.stream_write(0, Bytes::from_static(b"OverQUIC"), true),
        Ok(8)
    );
    // after receiving max_data frame, tx_cap is 30, sent 18, so tx_cap is 12 now.
    assert_eq!(map.tx_capacity(), 12);
    assert_eq!(map.tx_data(), 18);

    let stream = map.get_mut(0).unwrap();
    assert!(stream.is_sendable());
    assert!(!stream.is_writable());

    let mut buf = vec![0; 18];
    assert_eq!(stream.send.read(&mut buf), Ok((18, true)));
    assert_eq!(&buf[..], b"EverythingOverQUIC");
}

#[test]
fn stream_write_after_recv_stop_sending() {
    let local_tp = StreamTransportParams {
        initial_max_streams_bidi: 5,
        ..StreamTransportParams::default()
    };

    let peer_tp = StreamTransportParams {
        initial_max_data: 20,
        initial_max_stream_data_bidi_remote: 15,
        ..StreamTransportParams::default()
    };

    // 1. Creat a server StreamMap.
    let mut map = StreamMap::new(true, 50, 50, local_tp);
    map.update_peer_stream_transport_params(peer_tp);

    // 2. Receive a STOP_SENDING frame from client.
    assert!(map.on_stop_sending_frame_received(0, 7).is_ok());
    // Stream should be inserted into map.writable once STOP_SENDING frame is received.
    assert!(map.writable.contains(&0));

    // 3. Try to write data to stream(0), but it is stopped, so return StreamStopped error.
    assert_eq!(
        map.stream_write(0, Bytes::from_static(b"Q"), false),
        Err(Error::StreamStopped(7))
    );
}

// Test StreamMap::stream_writable
#[test]
fn stream_writable() {
    let local_tp = StreamTransportParams {
        initial_max_streams_bidi: 5,
        ..StreamTransportParams::default()
    };

    let peer_tp = StreamTransportParams {
        initial_max_data: 20,
        initial_max_stream_data_bidi_local: 15,
        ..StreamTransportParams::default()
    };

    // Creat a server StreamMap.
    let mut map = StreamMap::new(true, 50, 50, local_tp);
    map.update_peer_stream_transport_params(peer_tp);

    // Create a new client initiated bidi stream.
    assert!(map.get_or_create(0, false).is_ok());

    // 1. Stream has more than `len` bytes of send-side capacity.
    assert_eq!(map.stream_writable(0, 15), Ok(true));

    // 2. Stream blocked by stream-level flow control limit.
    assert_eq!(map.stream_writable(0, 16), Ok(false));
    assert_eq!(
        map.blocked().map(|(&k, &v)| (k, v)).collect::<Vec<_>>(),
        vec![(0, 15)]
    );

    // 3. Stream blocked by connection-level flow control limit.
    assert_eq!(map.stream_writable(0, 25), Ok(false));
    assert_eq!(map.send_capacity.blocked_at, Some(20));
}

// Test StreamMap::stream_set_priority
#[test]
fn stream_set_priority() {
    let peer_tp = StreamTransportParams {
        initial_max_streams_bidi: 1,
        ..StreamTransportParams::default()
    };

    // Create a client StreamMap.
    let mut map = StreamMap::new(false, 50, 50, StreamTransportParams::default());
    map.update_peer_stream_transport_params(peer_tp);

    // 1. Set priority on an invalid stream.
    assert_eq!(
        map.stream_set_priority(1, 1, true),
        Err(Error::StreamStateError)
    );

    // 2. Set priority on a not created stream.
    assert!(map.stream_set_priority(0, 1, true).is_ok());
    let stream = map.get(0).unwrap();
    assert_eq!((stream.urgency, stream.incremental), (1, true));

    // 3. Set priority on a stream with duplicate priority.
    assert!(map.stream_set_priority(0, 1, true).is_ok());
    let stream = map.get(0).unwrap();
    assert_eq!((stream.urgency, stream.incremental), (1, true));

    // 4. Set priority on a stream with different priority.
    assert!(map.stream_set_priority(0, 2, false).is_ok());
    let stream = map.get(0).unwrap();
    assert_eq!((stream.urgency, stream.incremental), (2, false));

    // 5. Set priority on a closed(0, simulation, not true) stream.
    map.mark_closed(0, true);
    assert!(map.stream_set_priority(0, 1, true).is_ok());
}

// Test StreamMap::stream_shutdown
#[test]
fn stream_shutdown_invalid_direction() {
    let local_tp = StreamTransportParams {
        initial_max_streams_uni: 5,
        ..StreamTransportParams::default()
    };

    let mut map = StreamMap::new(true, 50, 50, local_tp);
    map.concurrency_control.update_peer_max_streams(false, 5);

    assert!(map.get_or_create(2, false).is_ok());
    assert!(map.get_or_create(3, true).is_ok());

    // Local initiated unidirectional stream should not be shutdown in the receive-side.
    assert_eq!(
        map.stream_shutdown(3, Shutdown::Read, 0),
        Err(Error::StreamStateError)
    );

    // Peer initiated unidirectional stream should not be shutdown in the send-side.
    assert_eq!(
        map.stream_shutdown(2, Shutdown::Write, 0),
        Err(Error::StreamStateError)
    );
}

#[test]
fn stream_shutdown_not_exist() {
    let mut map = StreamMap::new(false, 50, 50, StreamTransportParams::default());

    assert_eq!(map.stream_shutdown(0, Shutdown::Read, 0), Err(Error::Done));

    assert_eq!(map.stream_shutdown(0, Shutdown::Write, 0), Err(Error::Done));
}

#[test]
fn stream_shutdown_read_should_update_flow_control() {
    let local_tp = StreamTransportParams {
        initial_max_data: 14,
        initial_max_stream_data_bidi_remote: 10,
        initial_max_streams_bidi: 2,
        ..StreamTransportParams::default()
    };

    let mut map = StreamMap::new(true, 50, 50, local_tp);

    // Receive a stream frame from stream 0, range is [0, 10), fin = false.
    assert!(map
        .on_stream_frame_received(0, 0, 10, false, Bytes::from_static(b"Everything"))
        .is_ok());
    assert!(map.readable.contains(&0));
    assert!(map.stream_shutdown(0, Shutdown::Read, 10).is_ok());

    // init_max_data: 14, window: 14, read_off: 10
    // available_window: 4 < window / 2, should update max_data.
    assert_eq!(map.flow_control.max_data(), 14);
    assert_eq!(map.flow_control.max_data_next(), 24);
    assert!(map.flow_control.should_send_max_data());
    assert!(map.rx_almost_full);
}

// Test StreamMap::{stream_read, stream_readable, stream_finished}
#[test]
fn stream_read_invalid_sid() {
    // MUST NOT read from local initiated unidirectional stream.
    let mut map = StreamMap::new(true, 50, 50, StreamTransportParams::default());
    let mut buf = vec![0; 1];
    assert_eq!(map.stream_read(3, &mut buf), Err(Error::StreamStateError));
}

#[test]
fn stream_read_and_finished_basic_logic() {
    let local_tp = StreamTransportParams {
        initial_max_data: 20,
        initial_max_stream_data_bidi_remote: 20,
        initial_max_streams_bidi: 5,
        ..StreamTransportParams::default()
    };

    let mut map = StreamMap::new(true, 50, 50, local_tp);

    // 1. Stream 0 is not exist, return StreamStateError.
    let mut buf = vec![0; 1];
    assert_eq!(map.stream_read(0, &mut buf), Err(Error::StreamStateError));

    // 2. Receive a stream frame, range is [0, 10), fin = false.
    assert_eq!(
        map.on_stream_frame_received(0, 0, 10, false, Bytes::from_static(b"Everything")),
        Ok(())
    );
    assert!(map.stream_readable(0));

    // 3. Read data from the stream.
    let mut buf = vec![0; 10];
    assert_eq!(map.stream_read(0, &mut buf), Ok((10, false)));
    assert_eq!(&buf[..10], b"Everything");
    assert!(!map.stream_finished(0));
    assert!(!map.stream_readable(0));

    // 4. There is no data to read, so return Done.
    let mut buf = vec![0; 1];
    assert_eq!(map.stream_read(0, &mut buf), Err(Error::Done));

    // 5. Receive a stream frame, range is [10, 18), fin = true.
    assert!(map
        .on_stream_frame_received(0, 10, 8, true, Bytes::from_static(b"OverQUIC"))
        .is_ok());
    assert!(!map.stream_finished(0));
    assert!(map.stream_readable(0));

    // 6. Read data from the stream.
    let mut buf = vec![0; 8];
    assert_eq!(map.stream_read(0, &mut buf), Ok((8, true)));
    assert_eq!(&buf[..8], b"OverQUIC");

    // 7. Stream receive-side is finished, and stream is not readable.
    assert!(map.stream_finished(0));
    assert!(!map.stream_readable(0));
}

// Test StreamMap::stream_capacity
#[test]
fn stream_capacity_not_exist() {
    let map = StreamMap::new(false, 50, 50, StreamTransportParams::default());

    assert_eq!(map.stream_capacity(0), Err(Error::StreamStateError));
}

#[test]
fn stream_capacity_stopped() {
    let local_tp = StreamTransportParams {
        initial_max_data: 20,
        initial_max_stream_data_bidi_remote: 20,
        initial_max_streams_bidi: 5,
        ..StreamTransportParams::default()
    };

    let mut map = StreamMap::new(true, 50, 50, local_tp);

    assert!(map.on_stop_sending_frame_received(4, 7).is_ok());
    assert_eq!(map.stream_capacity(4), Err(Error::StreamStopped(7)))
}

#[test]
fn stream_capacity() {
    let peer_tp = StreamTransportParams {
        initial_max_data: 20,
        initial_max_stream_data_bidi_remote: 15,
        initial_max_streams_bidi: 5,
        ..StreamTransportParams::default()
    };

    // 1. Creat a client StreamMap.
    let mut map = StreamMap::new(false, 50, 50, StreamTransportParams::default());
    map.update_peer_stream_transport_params(peer_tp);

    // 2. Create a stream(0) and write data to it.
    assert_eq!(
        map.stream_write(0, Bytes::from_static(b"Everything"), false),
        Ok(10)
    );
    assert_eq!(map.tx_data(), 10);
    assert_eq!(map.tx_capacity(), 10);
    // self.tx_cap > stream.send.capacity
    assert_eq!(map.stream_capacity(0), Ok(5));

    // 3. Receive a MAX_STREAM_DATA frame, stream(0) capacity is increased.
    assert!(map.on_max_stream_data_frame_received(0, 50).is_ok());
    // self.tx_cap < stream.send.capacity
    assert_eq!(map.stream_capacity(0), Ok(10));
}

// Test StreamMap::new
#[test]
fn stream_map_new() {
    let local_tp = StreamTransportParams {
        initial_max_data: 100,
        initial_max_stream_data_bidi_local: 50,
        initial_max_stream_data_bidi_remote: 50,
        initial_max_stream_data_uni: 50,
        initial_max_streams_bidi: 5,
        initial_max_streams_uni: 5,
    };

    let peer_tp = StreamTransportParams::default();
    let map = StreamMap::new(true, 50, 50, local_tp.clone());

    assert!(map.is_server, "current role is server");
    assert_eq!(map.streams.len(), 0);
    assert!(map.sendable.is_empty(), "sendable is empty");
    assert!(map.readable.is_empty(), "readable is empty");
    assert!(map.writable.is_empty(), "writable is empty");
    assert!(map.reset.is_empty(), "reset is empty");
    assert!(map.stopped.is_empty(), "stopped is empty");
    assert!(map.closed.is_empty(), "closed is empty");
    assert!(map.almost_full.is_empty(), "almost_full is empty");
    assert!(map.data_blocked.is_empty(), "data_blocked is empty");

    // Check concurrency limits
    assert_eq!(map.concurrency_control, ConcurrencyControl::new(5, 5));

    // Check connection-level flow control
    assert_eq!(map.flow_control.window(), 100);
    assert_eq!(map.flow_control.max_data(), 100);
    assert!(
        !map.flow_control.should_send_max_data(),
        "should not update max_data"
    );

    assert_eq!(map.max_stream_window, 50);
    assert_eq!(map.max_recv_off(), 0);
    assert_eq!(map.tx_data(), 0);
    assert_eq!(map.max_tx_data(), 0);
    assert_eq!(map.rx_almost_full, false);
    assert_eq!(map.data_blocked_at(), None);
    assert_eq!(map.local_transport_params, local_tp);
    assert_eq!(map.peer_transport_params, peer_tp);
}

// Test StreamMap::max_stream_data_limit
#[test]
fn stream_map_max_stream_data_limit() {
    let local_tp = StreamTransportParams {
        initial_max_data: 100,
        initial_max_stream_data_bidi_local: 11,
        initial_max_stream_data_bidi_remote: 12,
        initial_max_stream_data_uni: 13,
        initial_max_streams_bidi: 14,
        initial_max_streams_uni: 15,
    };

    let peer_tp = StreamTransportParams {
        initial_max_data: 200,
        initial_max_stream_data_bidi_local: 21,
        initial_max_stream_data_bidi_remote: 22,
        initial_max_stream_data_uni: 23,
        initial_max_streams_bidi: 24,
        initial_max_streams_uni: 25,
    };

    for (local, bidi, max_rx_data, max_tx_data) in vec![
        // local initiated bidi stream
        (true, true, 11, 22),
        // local initiated uni stream
        (true, false, 0, 23),
        // remote initiated bidi stream
        (false, true, 12, 21),
        // remote initiated uni stream
        (false, false, 13, 0),
    ] {
        assert_eq!(
            StreamMap::max_stream_data_limit(local, bidi, &local_tp, &peer_tp),
            (max_rx_data, max_tx_data)
        );
    }
}

// Test StreamMap::{get, get_mut, get_or_create}
#[test]
fn stream_map_get_or_create() {
    let local_tp = StreamTransportParams {
        initial_max_streams_bidi: 10,
        initial_max_streams_uni: 5,
        ..StreamTransportParams::default()
    };

    let peer_tp = StreamTransportParams {
        initial_max_streams_bidi: 30,
        initial_max_streams_uni: 15,
        ..StreamTransportParams::default()
    };

    let mut map = StreamMap::new(true, 50, 50, local_tp);
    map.update_peer_stream_transport_params(peer_tp);

    for stream_id in [4, 8, 12, 36, 6, 14, 10, 18, 5, 13, 9, 117, 7, 15, 11, 59] {
        assert!(map.get(stream_id).is_none(), "get unexpected stream");
        assert!(
            map.get_mut(stream_id).is_none(),
            "get_mut unexpected stream"
        );
    }

    // 1. Auto open streams
    // 1.1 Auto open client-initiated bidi stream
    //     36 is the highest stream-id that can be auto-opened
    for stream_id in [4, 12, 8, 36] {
        assert!(!is_local(stream_id, true), "stream id is client initiated");
        assert!(is_bidi(stream_id), "stream id is bidirectional");
        assert!(
            map.get_or_create(stream_id, false).is_ok(),
            "auto open client-initiated bidi stream"
        );
    }

    for stream_id in [4, 8, 12, 36] {
        assert!(map.get(stream_id).is_some(), "get stream {}", stream_id);
        assert!(
            map.get_mut(stream_id).is_some(),
            "get_mut stream {}",
            stream_id
        );
    }

    // 1.2 Auto open client-initiated uni stream
    //     18 is the highest stream-id that can be auto-opened
    for stream_id in [6, 14, 10, 18] {
        assert!(!is_local(stream_id, true), "stream id is client initiated");
        assert!(!is_bidi(stream_id), "stream id is unidirectional");
        assert!(
            map.get_or_create(stream_id, false).is_ok(),
            "auto open client-initiated uni stream"
        );
    }

    for stream_id in [6, 10, 14, 18] {
        assert!(map.get(stream_id).is_some(), "get stream {}", stream_id);
        assert!(
            map.get_mut(stream_id).is_some(),
            "get_mut stream {}",
            stream_id
        );
    }

    // 1.3 Auto open server-initiated bidi stream
    //     117 is the highest stream-id that can be auto-opened
    for stream_id in [5, 13, 9, 117] {
        assert!(is_local(stream_id, true), "stream id is server initiated");
        assert!(is_bidi(stream_id), "stream id is bidirectional");
        assert!(
            map.get_or_create(stream_id, true).is_ok(),
            "auto open server-initiated bidi stream"
        );
    }

    for stream_id in [5, 9, 13, 117] {
        assert!(map.get(stream_id).is_some(), "get stream {}", stream_id);
        assert!(
            map.get_mut(stream_id).is_some(),
            "get_mut stream {}",
            stream_id
        );
    }

    // 1.4 Auto open server-initiated uni stream
    //     59 is the highest stream-id that can be auto-opened
    for stream_id in [7, 15, 11, 59] {
        assert!(is_local(stream_id, true), "stream id is server initiated");
        assert!(!is_bidi(stream_id), "stream id is unidirectional");
        assert!(
            map.get_or_create(stream_id, true).is_ok(),
            "auto open server-initiated uni stream"
        );
    }

    for stream_id in [7, 11, 15, 59] {
        assert!(map.get(stream_id).is_some(), "get stream {}", stream_id);
        assert!(
            map.get_mut(stream_id).is_some(),
            "get_mut stream {}",
            stream_id
        );
    }

    // 2 Open too many streams
    // 2.1 Client opened too many bidi streams
    assert_eq!(
        map.get_or_create(40, false).err(),
        Some(Error::StreamLimitError),
        "stream limit should be exceeded"
    );

    // 2.2 Client opened too many uni streams
    assert_eq!(
        map.get_or_create(22, false).err(),
        Some(Error::StreamLimitError),
        "stream limit should be exceeded"
    );

    // 2.3 Server opened too many bidi streams
    assert_eq!(
        map.get_or_create(121, true).err(),
        Some(Error::StreamLimitError),
        "stream limit should be exceeded"
    );

    // 2.4 Server opened too many uni streams
    assert_eq!(
        map.get_or_create(63, true).err(),
        Some(Error::StreamLimitError),
        "stream limit should be exceeded"
    );

    for stream_id in [40, 22, 121, 63] {
        assert!(map.get(stream_id).is_none(), "get unexpected stream");
        assert!(
            map.get_mut(stream_id).is_none(),
            "get_mut unexpected stream"
        );
    }

    // 3. Open streams with wrong direction
    // 3.1 Client open server-initiated bidi stream
    assert_eq!(
        map.get_or_create(1, false).err(),
        Some(Error::StreamStateError),
        "stream direction is wrong"
    );

    // 3.2 Client open server-initiated uni stream
    assert_eq!(
        map.get_or_create(3, false).err(),
        Some(Error::StreamStateError),
        "stream direction is wrong"
    );

    // 3.3 Server open client-initiated bidi stream
    assert_eq!(
        map.get_or_create(0, true).err(),
        Some(Error::StreamStateError),
        "stream direction is wrong"
    );

    // 3.4 Server open client-initiated uni stream
    assert_eq!(
        map.get_or_create(2, true).err(),
        Some(Error::StreamStateError),
        "stream direction is wrong"
    );

    for stream_id in [0, 1, 2, 3] {
        assert!(map.get(stream_id).is_none(), "get unexpected stream");
        assert!(
            map.get_mut(stream_id).is_none(),
            "get_mut unexpected stream"
        );
    }
}

// Test StreamMap::{push_sendable, peek_sendable, remove_sendable}
#[test]
fn stream_map_sendable() {
    // Streams are categorized based on their urgency, where each urgency level
    // has two queues, including non-incremental and incremental streams.
    //
    // Streams with lower urgency level are scheduled first, and within the
    // same urgency level non-incremental streams are scheduled before incremental
    // streams.
    //
    // Non-incremental streams are scheduled in the order of their stream IDs.
    // Incremental streams are scheduled in a round-robin fashion.

    let mut map = StreamMap::new(true, 50, 50, StreamTransportParams::default());
    assert!(
        !map.has_sendable_streams(),
        "sendable stream should not exist"
    );

    // 1.Peek multiple times consecutively, the result should be the same.
    map.push_sendable(4, 7, false);
    assert!(map.has_sendable_streams());
    assert_eq!(map.peek_sendable(), Some(4));
    assert_eq!(map.peek_sendable(), Some(4));
    map.remove_sendable();

    // 2.Streams with lower urgency level are scheduled first.
    map.push_sendable(4, 2, false);
    map.push_sendable(8, 3, false);
    map.push_sendable(12, 1, false);
    assert_eq!(map.peek_sendable(), Some(12));
    map.remove_sendable();
    assert_eq!(map.peek_sendable(), Some(4));
    map.remove_sendable();
    assert_eq!(map.peek_sendable(), Some(8));
    map.remove_sendable();

    // 3.Within the same urgency level non-incremental streams are scheduled
    // before incremental streams.
    map.push_sendable(4, 7, true);
    map.push_sendable(8, 7, false);
    assert_eq!(map.peek_sendable(), Some(8));
    map.remove_sendable();
    assert_eq!(map.peek_sendable(), Some(4));
    map.remove_sendable();

    // 4.Non-incremental streams are scheduled in the order of their stream IDs.
    map.push_sendable(12, 7, false);
    map.push_sendable(4, 7, false);
    map.push_sendable(8, 7, false);
    assert_eq!(map.peek_sendable(), Some(4));
    map.remove_sendable();
    assert_eq!(map.peek_sendable(), Some(8));
    map.remove_sendable();
    assert_eq!(map.peek_sendable(), Some(12));
    map.remove_sendable();

    // 5.Incremental streams are scheduled in a round-robin fashion.
    map.push_sendable(12, 7, true);
    map.push_sendable(8, 7, true);
    map.push_sendable(4, 7, true);
    assert_eq!(map.peek_sendable(), Some(12));
    assert_eq!(map.peek_sendable(), Some(8));
    assert_eq!(map.peek_sendable(), Some(4));
    assert_eq!(map.peek_sendable(), Some(12));
    assert_eq!(map.peek_sendable(), Some(8));
    assert_eq!(map.peek_sendable(), Some(4));
    map.remove_sendable();
    map.remove_sendable();
    map.remove_sendable();

    assert!(
        !map.has_sendable_streams(),
        "sendable stream should not exist"
    );
}

// Test StreamMap::mark_readable
#[test]
fn stream_map_readable() {
    let mut map = StreamMap::new(true, 50, 50, StreamTransportParams::default());
    assert!(map.readable.is_empty(), "readable stream should not exist");

    // Insert multiple streams unordered.
    for stream_id in [4, 8, 12, 0, 16] {
        map.mark_readable(stream_id, true);
    }
    assert!(!map.readable.is_empty());

    let mut v = map.readable_iter().collect::<Vec<u64>>();
    assert_eq!(v.len(), 5);
    v.sort();
    assert_eq!(v, vec![0, 4, 8, 12, 16]);

    // Do nothing if `readable` is true but the stream was already in the list.
    for stream_id in [4, 8, 12, 0, 16] {
        map.mark_readable(stream_id, true);
    }
    assert_eq!(map.readable_iter().collect::<Vec<u64>>().len(), 5);

    // Remove streams from the list if `readable` is false.
    for stream_id in [4, 8, 12, 0, 16] {
        map.mark_readable(stream_id, false);
    }
    assert!(map.readable.is_empty());
}

// Test StreamMap::mark_writable
#[test]
fn stream_map_writable() {
    let mut map = StreamMap::new(true, 50, 50, StreamTransportParams::default());
    assert!(map.writable.is_empty(), "writable stream should not exist");

    // Insert multiple streams unordered.
    for stream_id in [4, 8, 12, 0, 16] {
        map.mark_writable(stream_id, true);
    }
    assert!(!map.writable.is_empty());

    let mut v = map.writable_iter().collect::<Vec<u64>>();
    assert_eq!(v.len(), 5);
    v.sort();
    assert_eq!(v, vec![0, 4, 8, 12, 16]);

    // Do nothing if `writable` is true but the stream was already in the list.
    for stream_id in [4, 8, 12, 0, 16] {
        map.mark_writable(stream_id, true);
    }
    assert_eq!(map.writable_iter().collect::<Vec<u64>>().len(), 5);

    // Remove streams from the list if `writable` is false.
    for stream_id in [4, 8, 12, 0, 16] {
        map.mark_writable(stream_id, false);
    }
    assert!(map.writable.is_empty());
}

// Test StreamMap::mark_almost_full
#[test]
fn stream_map_almost_full() {
    let mut map = StreamMap::new(true, 50, 50, StreamTransportParams::default());
    assert!(
        map.almost_full.is_empty(),
        "almost_full stream should not exist"
    );

    // Insert multiple streams unordered.
    for stream_id in [4, 8, 12, 0, 16] {
        map.mark_almost_full(stream_id, true);
    }
    assert!(!map.almost_full.is_empty());

    let mut v = map.almost_full().collect::<Vec<u64>>();
    assert_eq!(v.len(), 5);
    v.sort();
    assert_eq!(v, vec![0, 4, 8, 12, 16]);

    // Do nothing if `almost_full` is true but the stream was already in the list.
    for stream_id in [4, 8, 12, 0, 16] {
        map.mark_almost_full(stream_id, true);
    }
    assert_eq!(map.almost_full().collect::<Vec<u64>>().len(), 5);

    // Remove streams from the list if `almost_full` is false.
    for stream_id in [4, 8, 12, 0, 16] {
        map.mark_almost_full(stream_id, false);
    }
    assert!(map.almost_full.is_empty());
}

// Test StreamMap::mark_closed
#[test]
fn stream_map_closed() {
    let local_tp = StreamTransportParams {
        initial_max_data: 100,
        initial_max_stream_data_bidi_local: 50,
        initial_max_stream_data_bidi_remote: 50,
        initial_max_stream_data_uni: 50,
        initial_max_streams_bidi: 10,
        initial_max_streams_uni: 5,
    };

    let mut map = StreamMap::new(true, 50, 50, local_tp.clone());
    assert!(map.closed.is_empty(), "closed stream not empty");

    // Update the peer's max_streams limit for concurrency control.
    map.concurrency_control.update_peer_max_streams(true, 30);
    map.concurrency_control.update_peer_max_streams(false, 15);

    // Auto open 5 client-initiated bidi stream
    // [0, 4, 8, 12, 16]
    for seq in 0..=4 {
        let stream_id = seq * 4;
        assert!(
            !is_local(stream_id, true),
            "stream id is not client initiated"
        );
        assert!(is_bidi(stream_id), "stream id is unidirectional");
        assert!(
            map.get_or_create(stream_id, false).is_ok(),
            "auto open client-initiated bidi stream failed"
        );

        map.mark_writable(stream_id, true);
        map.mark_readable(stream_id, true);
    }
    assert_eq!(map.streams.len(), 5);
    assert_eq!(map.readable.len(), 5);
    assert_eq!(map.writable.len(), 5);

    // Auto open 3 client-initiated uni stream
    // [2, 6, 10]
    for seq in 0..=2 {
        let stream_id = seq * 4 + 2;
        assert!(
            !is_local(stream_id, true),
            "stream id is not client initiated"
        );
        assert!(!is_bidi(stream_id), "stream id is bidirectional");
        assert!(
            map.get_or_create(stream_id, false).is_ok(),
            "auto open client-initiated uni stream failed"
        );
        map.mark_writable(stream_id, true);
        map.mark_readable(stream_id, true);
    }
    assert_eq!(map.streams.len(), 8);
    assert_eq!(map.readable.len(), 8);
    assert_eq!(map.writable.len(), 8);

    // Auto open server-initiated bidi stream
    for stream_id in [5, 13, 9] {
        assert!(is_local(stream_id, true), "stream id is client initiated");
        assert!(is_bidi(stream_id), "stream id is unidirectional");
        assert!(
            map.get_or_create(stream_id, true).is_ok(),
            "auto open server-initiated bidi stream failed"
        );
        map.mark_writable(stream_id, true);
        map.mark_readable(stream_id, true);
    }
    assert_eq!(map.streams.len(), 11);
    assert_eq!(map.readable.len(), 11);
    assert_eq!(map.writable.len(), 11);

    // Auto open server-initiated uni stream
    for stream_id in [7, 15, 11] {
        assert!(is_local(stream_id, true), "stream id is client initiated");
        assert!(!is_bidi(stream_id), "stream id is bidirectional");
        assert!(
            map.get_or_create(stream_id, true).is_ok(),
            "auto open server-initiated uni stream failed"
        );
        map.mark_writable(stream_id, true);
        map.mark_readable(stream_id, true);
    }
    assert_eq!(map.streams.len(), 14);
    assert_eq!(map.readable.len(), 14);
    assert_eq!(map.writable.len(), 14);

    // Client opened too many bidi streams, blocked by local stream limit
    assert_eq!(
        map.get_or_create(40, false).err(),
        Some(Error::StreamLimitError),
        "stream limit should be exceeded"
    );
    // Client opened too many uni streams, blocked by local stream limit
    assert_eq!(
        map.get_or_create(22, false).err(),
        Some(Error::StreamLimitError),
        "stream limit should be exceeded"
    );

    assert_eq!(map.streams.len(), 14);
    assert_eq!(map.readable.len(), 14);
    assert_eq!(map.writable.len(), 14);

    // Mark 5 client-initiated bidi streams as closed, give back credit to the peer.
    // Close [0, 4, 8, 12, 16]
    for seq in 0..=4 {
        let stream_id = seq * 4;
        map.mark_closed(stream_id, false);
    }
    // Mark 2 client-initiated uni streams as closed, give back credit to the peer.
    // close [2, 6]
    for seq in 0..=1 {
        let stream_id = seq * 4 + 2;
        map.mark_closed(stream_id, false);
    }
    assert_eq!(map.streams.len(), 7);
    assert_eq!(map.readable.len(), 7);
    assert_eq!(map.writable.len(), 7);
    assert_eq!(map.closed.len(), 7);

    assert_eq!(map.max_streams_next(true), 15);
    assert_eq!(map.max_streams_next(false), 7);

    assert!(
        !map.should_update_local_max_streams(true),
        "bidi streams limit should not be updated"
    );
    assert!(
        !map.should_update_local_max_streams(false),
        "uni streams limit should not be updated"
    );

    map.mark_closed(5, true);
    map.mark_closed(7, true);
    assert!(
        !map.should_update_local_max_streams(true),
        "close local bidi stream should not affect local bidi streams limit"
    );
    assert!(
        !map.should_update_local_max_streams(false),
        "close local uni stream should not affect local uni streams limit"
    );
    assert_eq!(map.streams.len(), 5);
    assert_eq!(map.readable.len(), 5);
    assert_eq!(map.writable.len(), 5);
    assert_eq!(map.closed.len(), 9);

    // Auto open client-initiated bidi stream, id: 20
    assert!(
        map.get_or_create(20, false).is_ok(),
        "auto open client-initiated bidi stream failed"
    );
    // (15 - 10) > (10 - 6), should update
    assert_eq!(map.max_streams_next(true), 15);
    assert!(
        map.should_update_local_max_streams(true),
        "should update local bidi streams limit"
    );

    map.mark_closed(10, false);
    assert_eq!(map.max_streams_next(false), 8);
    // (8 - 5) > (5 - 3), should update
    assert!(
        map.should_update_local_max_streams(false),
        "should update local uni streams limit"
    );

    assert_eq!(map.streams.len(), 5);
    assert_eq!(map.readable.len(), 4);
    assert_eq!(map.writable.len(), 4);
    assert_eq!(map.closed.len(), 10);

    map.update_local_max_streams(true);
    assert_eq!(map.max_streams(true), 15);
    map.update_local_max_streams(false);
    assert_eq!(map.max_streams(false), 8);

    assert!(
        map.get_or_create(40, false).is_ok(),
        "auto open client-initiated bidi stream failed"
    );
    assert!(
        map.get_or_create(22, false).is_ok(),
        "auto open client-initiated uni stream failed"
    );
    assert_eq!(map.streams.len(), 7);

    let mut v = map.closed.iter().copied().collect::<Vec<u64>>();
    assert_eq!(v.len(), 10);
    v.sort();
    assert_eq!(v, vec![0, 2, 4, 5, 6, 7, 8, 10, 12, 16]);
}

// Test StreamMap::mark_reset
#[test]
fn stream_map_reset() {
    let mut map = StreamMap::new(true, 50, 50, StreamTransportParams::default());
    assert!(map.reset.is_empty(), "reset stream should not exist");

    // Insert multiple streams unordered.
    for seq in [1, 2, 3, 0, 4] {
        let stream_id = seq * 4;
        map.mark_reset(stream_id, true, seq, seq);
    }
    assert!(!map.reset.is_empty());
    assert_eq!(map.reset.len(), 5);

    let mut v = map.reset().map(|(&k, &v)| (k, v)).collect::<Vec<_>>();
    assert_eq!(v.len(), 5);
    v.sort();
    assert_eq!(
        v,
        vec![0, 1, 2, 3, 4]
            .into_iter()
            .map(|x| (x * 4, (x, x)))
            .collect::<Vec<_>>()
    );

    // If `reset` is true but the stream was already in the list, the error code
    // and the final size will be updated.
    for seq in [1, 2, 3, 0, 4] {
        let stream_id = seq * 4;
        map.mark_reset(stream_id, true, seq + 1, seq + 1);
    }
    let mut v = map.reset().map(|(&k, &v)| (k, v)).collect::<Vec<_>>();
    assert_eq!(v.len(), 5);
    v.sort();
    assert_eq!(
        v,
        vec![0, 1, 2, 3, 4]
            .into_iter()
            .map(|x| (x * 4, (x + 1, x + 1)))
            .collect::<Vec<_>>()
    );

    // Remove streams from the list if `reset` is false.
    for stream_id in [4, 8, 12, 0, 16] {
        map.mark_reset(stream_id, false, 0, 0);
    }
    assert!(map.reset.is_empty());
}

// Test StreamMap::mark_blocked
#[test]
fn stream_map_blocked() {
    let mut map = StreamMap::new(true, 50, 50, StreamTransportParams::default());
    assert!(map.reset.is_empty(), "blocked stream should not exist");

    // Insert multiple streams unordered.
    for seq in [1, 2, 3, 0, 4] {
        let stream_id = seq * 4;
        map.mark_blocked(stream_id, true, seq * 100);
    }
    assert!(!map.data_blocked.is_empty());
    assert_eq!(map.data_blocked.len(), 5);

    let mut v = map.blocked().map(|(&k, &v)| (k, v)).collect::<Vec<_>>();
    assert_eq!(v.len(), 5);
    v.sort();
    assert_eq!(
        v,
        vec![0, 1, 2, 3, 4]
            .into_iter()
            .map(|x| (x * 4, x * 100))
            .collect::<Vec<_>>()
    );

    // If `blocked` is true but the stream was already in the list, the offset
    // will be updated.
    for seq in [1, 2, 3, 0, 4] {
        let stream_id = seq * 4;
        map.mark_blocked(stream_id, true, seq * 200);
    }
    let mut v = map.blocked().map(|(&k, &v)| (k, v)).collect::<Vec<_>>();
    assert_eq!(v.len(), 5);
    v.sort();
    assert_eq!(
        v,
        vec![0, 1, 2, 3, 4]
            .into_iter()
            .map(|x| (x * 4, x * 200))
            .collect::<Vec<_>>()
    );

    // Remove streams from the list if `blocked` is false.
    for stream_id in [4, 8, 12, 0, 16] {
        map.mark_blocked(stream_id, false, 0);
    }
    assert!(map.data_blocked.is_empty());
}

// Test StreamMap::mark_stopped
#[test]
fn stream_map_stopped() {
    let mut map = StreamMap::new(true, 50, 50, StreamTransportParams::default());
    assert!(map.reset.is_empty(), "stopped stream should not exist");

    // Insert multiple streams unordered.
    for seq in [1, 2, 3, 0, 4] {
        let stream_id = seq * 4;
        map.mark_stopped(stream_id, true, seq);
    }
    assert!(!map.stopped.is_empty());
    assert_eq!(map.stopped.len(), 5);

    let mut v = map.stopped().map(|(&k, &v)| (k, v)).collect::<Vec<_>>();
    assert_eq!(v.len(), 5);
    v.sort();
    assert_eq!(
        v,
        vec![0, 1, 2, 3, 4]
            .into_iter()
            .map(|x| (x * 4, x))
            .collect::<Vec<_>>()
    );

    // If `stopped` is true but the stream was already in the list, the offset
    // will be updated.
    for seq in [1, 2, 3, 0, 4] {
        let stream_id = seq * 4;
        map.mark_stopped(stream_id, true, seq * 2);
    }
    let mut v = map.stopped().map(|(&k, &v)| (k, v)).collect::<Vec<_>>();
    assert_eq!(v.len(), 5);
    v.sort();
    assert_eq!(
        v,
        vec![0, 1, 2, 3, 4]
            .into_iter()
            .map(|x| (x * 4, x * 2))
            .collect::<Vec<_>>()
    );

    // Remove streams from the list if `stopped` is false.
    for stream_id in [4, 8, 12, 0, 16] {
        map.mark_stopped(stream_id, false, 0);
    }
    assert!(map.stopped.is_empty());
}

// Test StreamMap::on_max_data_frame_received
#[test]
fn stream_map_on_max_data_frame_received() {
    let mut map = StreamMap::new(true, 50, 50, StreamTransportParams::default());
    assert_eq!(map.max_tx_data(), 0);

    // Update max_data
    map.on_max_data_frame_received(100);
    assert_eq!(map.max_tx_data(), 100);

    // Assume that connection-level flow control is blocked at 150.
    map.update_data_blocked_at(Some(150));

    // Update max_data, but it doesn't change the blocked state.
    map.on_max_data_frame_received(130);
    assert_eq!(map.max_tx_data(), 130);
    assert_eq!(map.data_blocked_at(), Some(150));

    // Update max_data, and it changes the blocked state.
    map.on_max_data_frame_received(200);
    assert_eq!(map.max_tx_data(), 200);
    assert_eq!(map.data_blocked_at(), None);
}

// Test StreamMap::on_max_stream_data_frame_received
#[test]
fn stream_map_on_max_stream_data_frame_received() {
    let local_tp = StreamTransportParams {
        initial_max_data: 100,
        initial_max_stream_data_bidi_local: 50,
        initial_max_stream_data_bidi_remote: 50,
        initial_max_stream_data_uni: 50,
        initial_max_streams_bidi: 10,
        initial_max_streams_uni: 5,
    };

    let mut map = StreamMap::new(true, 50, 50, local_tp);

    // Update the peer's max_streams limit for concurrency control.
    map.concurrency_control.update_peer_max_streams(true, 30);
    map.concurrency_control.update_peer_max_streams(false, 15);

    // An endpoint that receives a MAX_STREAM_DATA frame for a receive-only stream
    // MUST terminate the connection with error STREAM_STATE_ERROR.
    assert_eq!(
        map.on_max_stream_data_frame_received(2, 100),
        Err(Error::StreamStateError)
    );

    // Client open too many bidi streams, get_or_create return StreamLimitError.
    assert_eq!(
        map.on_max_stream_data_frame_received(40, 100),
        Err(Error::StreamLimitError)
    );

    // Create a new bidi stream, it is not sendable, but it is writable.
    assert!(map.on_max_stream_data_frame_received(4, 10).is_ok());
    assert!(map.writable.contains(&4));
    let stream = map.get_mut(4).unwrap();
    assert_eq!(stream.send.max_data, 10);
    assert_eq!(
        stream.send.write(Bytes::from_static(b"Everything"), false),
        Ok(10)
    );
    assert_eq!(
        stream.send.write(Bytes::from_static(b"OverQUIC"), false),
        Ok(0)
    );

    // Update the peer's max stream data
    assert!(map.on_max_stream_data_frame_received(4, 18).is_ok());
    let stream = map.get_mut(4).unwrap();
    assert_eq!(stream.send.max_data, 18);
    assert_eq!(
        stream.send.write(Bytes::from_static(b"OverQUIC"), false),
        Ok(8)
    );

    // When stream's send-side flow control is exhausted,
    // write empty data with fin flag, it should be ok.
    assert_eq!(stream.send.write(Bytes::new(), true), Ok(0));

    // Shutdown the stream abruptly, it should be ok.
    assert_eq!(stream.send.shutdown(), Ok((0, 18)));
    // Here we call `write` to make sure the stream's fin_off is set.
    assert_eq!(stream.recv.write(0, Bytes::new(), true), Ok(()));
    assert!(stream.recv.shutdown().is_ok());
    assert_eq!(stream.is_complete(), true);
    map.mark_closed(4, false);
    assert!(
        map.on_max_stream_data_frame_received(4, 18).is_ok(),
        "Stream is already closed, just ignore the frame."
    );
}

// Test StreamMap::on_max_streams_frame_received
#[test]
fn stream_map_on_max_streams_frame_received() {
    let mut map = StreamMap::new(true, 50, 50, StreamTransportParams::default());
    assert_eq!(map.concurrency_control.peer_max_streams_bidi, 0);
    assert_eq!(map.concurrency_control.peer_max_streams_uni, 0);

    // 1. Server initiated bidi(101) and uni(103) stream, exceeding the limit.
    for (stream_id, local) in vec![
        // bidi
        (101, true),
        // uni
        (103, true),
    ] {
        assert_eq!(
            map.get_or_create(stream_id, local).err(),
            Some(Error::StreamLimitError)
        );
    }

    // 2. max_streams > 2^60, return FrameEncodingError
    for (max_streams, bidi) in vec![(1 << 61, true), (1 << 61, false)] {
        assert_eq!(
            map.on_max_streams_frame_received(max_streams, bidi),
            Err(Error::FrameEncodingError)
        );
    }

    // 3. Receive a MAX_STREAMS frame for the bidi stream
    assert_eq!(map.on_max_streams_frame_received(100, true), Ok(()));
    assert_eq!(map.concurrency_control.peer_max_streams_bidi, 100);
    assert!(map.get_or_create(101, true).is_ok());

    // 4. Receive a MAX_STREAMS frame for the uni stream
    assert_eq!(map.on_max_streams_frame_received(50, false), Ok(()));
    assert_eq!(map.concurrency_control.peer_max_streams_uni, 50);
    assert!(map.get_or_create(103, true).is_ok());
}

// Test StreamMap::on_stream_data_blocked_frame_received
#[test]
fn stream_map_on_stream_data_blocked_frame_received() {
    // 1. Server endpoint
    // 1.1 Receive a STREAM_DATA_BLOCKED frame for a local initiated send-only stream
    let mut map = StreamMap::new(true, 50, 50, StreamTransportParams::default());
    let stream_id = 3;
    assert!(is_local(stream_id, true));
    assert!(!is_bidi(stream_id));
    assert_eq!(
        map.on_stream_data_blocked_frame_received(stream_id, 100),
        Err(Error::StreamStateError)
    );

    // 1.2 Receive a STREAM_DATA_BLOCKED frame for a stream which allow receive data
    for stream_id in [0, 1, 2] {
        assert_eq!(
            map.on_stream_data_blocked_frame_received(stream_id, 100),
            Ok(())
        );
    }

    // 2. Client endpoint
    // 2.1 Receive a STREAM_DATA_BLOCKED frame for a local initiated send-only stream
    let mut map = StreamMap::new(false, 50, 50, StreamTransportParams::default());
    let stream_id = 2;
    assert!(is_local(stream_id, false));
    assert!(!is_bidi(stream_id));
    assert_eq!(
        map.on_stream_data_blocked_frame_received(stream_id, 100),
        Err(Error::StreamStateError)
    );

    // 2.2 Receive a STREAM_DATA_BLOCKED frame for a stream which allow receive data
    for stream_id in [0, 1, 3] {
        assert_eq!(
            map.on_stream_data_blocked_frame_received(stream_id, 100),
            Ok(())
        );
    }
}

// Test StreamMap::on_streams_blocked_frame_received
#[test]
fn stream_map_on_streams_blocked_frame_received() {
    let mut map = StreamMap::new(true, 50, 50, StreamTransportParams::default());

    for (max_streams, bidi, result) in vec![
        (1 << 61, true, Err(Error::FrameEncodingError)),
        (1 << 61, false, Err(Error::FrameEncodingError)),
        (1 << 60, true, Ok(())),
        (1 << 60, false, Ok(())),
    ] {
        assert_eq!(
            map.on_streams_blocked_frame_received(max_streams, bidi),
            result
        );
    }
}

// Test StreamMap::on_reset_stream_frame_received
#[test]
fn stream_map_on_reset_stream_frame_received() {
    let local_tp = StreamTransportParams {
        initial_max_data: 100,
        initial_max_stream_data_bidi_remote: 110,
        initial_max_streams_bidi: 10,
        ..StreamTransportParams::default()
    };

    // Create a server StreamMap
    let mut map = StreamMap::new(true, 50, 50, local_tp);

    // 1. Receive a RESET_STREAM frame for a local initiated uni stream(3)
    assert_eq!(
        map.on_reset_stream_frame_received(3, 0, 10),
        Err(Error::StreamStateError)
    );

    // 2. Peer open too many streams
    assert_eq!(
        map.on_reset_stream_frame_received(40, 0, 10),
        Err(Error::StreamLimitError)
    );

    // 3. Peer send too much data, which exceeds the connection flow control limit.
    assert_eq!(
        map.on_reset_stream_frame_received(36, 0, 101),
        Err(Error::FlowControlError)
    );
    assert_eq!(map.max_rx_data_left(), 100);

    // 4. Peer send too much data, which exceeds the stream flow control limit.
    assert_eq!(
        map.on_reset_stream_frame_received(0, 0, 111),
        Err(Error::FlowControlError)
    );

    // 5. Duplicate RESET_STREAM frame with same final size
    // stream_id: 4, final_size: 10
    assert_eq!(map.on_reset_stream_frame_received(4, 0, 10), Ok(()));
    assert_eq!(map.max_recv_off(), 10);
    assert_eq!(map.on_reset_stream_frame_received(4, 0, 10), Ok(()));
    assert_eq!(map.max_recv_off(), 10);
    // After receiving a RESET_STREAM frame, the stream receive-side is finished,
    // but the stream is still readable.
    let stream = map.get(4).unwrap();
    assert!(stream.recv.is_fin());
    assert!(map.readable.contains(&4));

    // 6. Duplicate RESET_STREAM frame with different final size
    // stream_id: 8, final_size: 10
    assert_eq!(map.on_reset_stream_frame_received(8, 0, 10), Ok(()));
    assert_eq!(map.max_recv_off(), 20);
    assert_eq!(
        map.on_reset_stream_frame_received(8, 0, 20),
        Err(Error::FinalSizeError)
    );
    assert_eq!(map.max_recv_off(), 20);

    // 7. Receive a RESET_STREAM frame for a stream which has received some data
    //    and final size is same with the maximum received offset.
    // stream_id: 12, max received offset: 20, final size: 20.
    assert_eq!(
        map.on_stream_frame_received(12, 10, 10, false, Bytes::from_static(b"Everything")),
        Ok(())
    );
    assert_eq!(map.on_reset_stream_frame_received(12, 0, 20), Ok(()));
    assert_eq!(map.get(12).unwrap().recv.recv_off, 20);
    assert_eq!(map.get(12).unwrap().recv.fin_off, Some(20));

    // 8. Receive a RESET_STREAM frame for a stream which has received some data
    //    and final size is less than the maximum received offset.
    // stream_id: 16, max received offset: 20, final size: 10.
    assert_eq!(
        map.on_stream_frame_received(16, 10, 10, false, Bytes::from_static(b"Everything")),
        Ok(())
    );
    assert_eq!(
        map.on_reset_stream_frame_received(16, 0, 10),
        Err(Error::FinalSizeError)
    );

    // 9. Receive a RESET_STREAM frame for a stream which has received some data
    //    and final size is greater than the maximum received offset.
    // stream_id: 20, max received offset: 20, final size: 30.
    assert_eq!(
        map.on_stream_frame_received(20, 10, 10, false, Bytes::from_static(b"Everything")),
        Ok(())
    );
    assert_eq!(map.get(20).unwrap().recv.recv_off, 20);
    assert_eq!(map.on_reset_stream_frame_received(20, 0, 30), Ok(()));
    assert_eq!(map.get(20).unwrap().recv.recv_off, 30);
    assert_eq!(map.get(20).unwrap().recv.fin_off, Some(30));

    // 10. Receive a RESET_STREAM frame for a stream which has been closed.
    // Shutdown the stream abruptly, it should be ok.
    let stream = map.get_or_create(24, false).unwrap();
    assert_eq!(stream.send.shutdown(), Ok((0, 0)));
    // Here we call `write` to make sure the stream's fin_off is set.
    assert_eq!(stream.recv.write(0, Bytes::new(), true), Ok(()));
    assert!(stream.recv.shutdown().is_ok());
    assert_eq!(stream.is_complete(), true);
    map.mark_closed(24, false);
    assert!(
        map.on_reset_stream_frame_received(24, 0, 0).is_ok(),
        "Stream is already closed, just ignore the frame."
    );
}

#[test]
fn stream_map_on_reset_stream_frame_received_flow_control_mechanism() {
    // Note: When a stream is reset, all buffered data will be discarded,
    // so consider the received data as consumed, which might trigger a
    // connection-level flow control update.

    let local_tp = StreamTransportParams {
        initial_max_data: 20,
        initial_max_stream_data_bidi_local: 50,
        initial_max_stream_data_bidi_remote: 50,
        initial_max_stream_data_uni: 50,
        initial_max_streams_bidi: 10,
        initial_max_streams_uni: 5,
    };

    let mut map = StreamMap::new(true, 50, 50, local_tp);
    assert_eq!(map.flow_control.window(), 20);
    assert_eq!(map.flow_control.max_data(), 20);

    // 1. Receive a RESET_STREAM frame for a stream which has received some data
    //    and final size is same with the maximum received offset.
    // stream_id: 4, max received offset: 4, read_off: 0, final size: 4.
    let stream = map.get_or_create(4, false).unwrap();
    assert_eq!(
        stream.recv.write(0, Bytes::from_static(b"QUIC"), false),
        Ok(())
    );
    assert_eq!(map.on_reset_stream_frame_received(4, 0, 4), Ok(()));
    // map.flow_control.consumed = 4
    assert_eq!(map.flow_control.max_data_next(), 24);
    assert!(
        !map.flow_control.should_send_max_data(),
        "available_window = 16 > 10 = window/2, not update max_data"
    );
    assert!(!map.rx_almost_full);

    // 2. Receive a RESET_STREAM frame for a stream which has received some data
    //    and final size is greater than the maximum received offset.
    // stream_id: 8, max received offset: 1, final size: 2.
    let stream = map.get_or_create(8, false).unwrap();
    assert_eq!(
        stream.recv.write(0, Bytes::from_static(b"QUICQUIC"), false),
        Ok(())
    );
    assert_eq!(map.on_reset_stream_frame_received(8, 0, 8), Ok(()));
    // map.flow_control.consumed = 12
    assert_eq!(map.flow_control.max_data_next(), 32);
    assert!(
        map.flow_control.should_send_max_data(),
        "available_window = 8 < 10 = window/2, update max_data"
    );
    assert!(map.rx_almost_full);
}

// Test StreamMap::on_stop_sending_frame_received
#[test]
fn stream_map_server_on_stop_sending_frame_received() {
    let is_server = true;
    let local_tp = StreamTransportParams {
        initial_max_data: 100,
        initial_max_stream_data_bidi_local: 50,
        initial_max_stream_data_bidi_remote: 50,
        initial_max_stream_data_uni: 50,
        initial_max_streams_bidi: 10,
        initial_max_streams_uni: 5,
    };
    let mut map = StreamMap::new(is_server, 50, 50, local_tp);

    // 1. Receive a STOP_SENDING frame for a peer initiated receive-only stream
    let stream_id = 2;
    assert!(!is_local(stream_id, is_server));
    assert!(!is_bidi(stream_id));
    assert_eq!(
        map.on_stop_sending_frame_received(stream_id, 0),
        Err(Error::StreamStateError)
    );

    // 2. Receive a STOP_SENDING frame for a locally initiated stream that has not yet been created
    let stream_id = 1;
    assert!(is_local(stream_id, is_server));
    assert!(is_bidi(stream_id));
    assert_eq!(
        map.on_stop_sending_frame_received(stream_id, 0),
        Err(Error::StreamStateError)
    );

    // 3. Peer open too many bidi streams
    //    get_or_create will return Error::StreamLimitError
    assert_eq!(
        map.on_stop_sending_frame_received(40, 0),
        Err(Error::StreamLimitError)
    );

    // 4. Duplicate STOP_SENDING frame
    // stream_id: 4
    assert_eq!(map.on_stop_sending_frame_received(4, 7), Ok(()));
    assert_eq!(map.tx_data(), 0);
    // Send a RESET_STREAM frame to the peer after receiving a STOP_SENDING frame.
    assert!(map.reset.contains_key(&4));
    // After receiving a STOP_SENDING frame, the stream send-side is complete,
    // but the stream is still writable.
    let stream = map.get(4).unwrap();
    assert_eq!(stream.send.is_complete(), true);
    assert!(map.writable.contains(&4));
    assert_eq!(stream.send.error, Some(7));
    assert!(stream.send.is_stopped());
    assert_eq!(stream.send.capacity(), Err(Error::StreamStopped(7)));

    assert_eq!(map.on_stop_sending_frame_received(4, 0), Ok(()));

    // 5. Receive a STOP_SENDING frame for a stream which has been closed.
    // Shutdown the stream abruptly, it should be ok.
    let stream = map.get_or_create(24, false).unwrap();
    assert_eq!(stream.send.shutdown(), Ok((0, 0)));
    // Here we call `write` to make sure the stream's fin_off is set.
    assert_eq!(stream.recv.write(0, Bytes::new(), true), Ok(()));
    assert!(stream.recv.shutdown().is_ok());
    assert_eq!(stream.is_complete(), true);
    map.mark_closed(24, false);
    assert!(
        map.on_stop_sending_frame_received(24, 0).is_ok(),
        "Stream is already closed, just ignore the frame."
    );
}

#[test]
fn stream_map_client_on_stop_sending_frame_received() {
    let is_server = false;
    let local_tp = StreamTransportParams {
        initial_max_data: 100,
        initial_max_stream_data_bidi_local: 50,
        initial_max_stream_data_bidi_remote: 50,
        initial_max_stream_data_uni: 50,
        initial_max_streams_bidi: 10,
        initial_max_streams_uni: 5,
    };
    let mut map = StreamMap::new(is_server, 50, 50, local_tp);

    // 1. Receive a STOP_SENDING frame for a peer initiated receive-only stream
    let stream_id = 3;
    assert!(!is_local(stream_id, is_server));
    assert!(!is_bidi(stream_id));
    assert_eq!(
        map.on_stop_sending_frame_received(stream_id, 0),
        Err(Error::StreamStateError)
    );

    // 2. Receive a STOP_SENDING frame for a locally initiated stream that has not yet been created
    let stream_id = 0;
    assert!(is_local(stream_id, is_server));
    assert!(is_bidi(stream_id));
    assert_eq!(
        map.on_stop_sending_frame_received(stream_id, 0),
        Err(Error::StreamStateError)
    );

    // 3. Peer open too many bidi streams
    //    get_or_create will return Error::StreamLimitError
    assert_eq!(
        map.on_stop_sending_frame_received(41, 0),
        Err(Error::StreamLimitError)
    );

    // 4. Duplicate STOP_SENDING frame
    // stream_id: 5
    assert_eq!(map.on_stop_sending_frame_received(5, 7), Ok(()));
    assert_eq!(map.tx_data(), 0);
    // Send a RESET_STREAM frame to the peer after receiving a STOP_SENDING frame.
    assert!(map.reset.contains_key(&5));
    // After receiving a STOP_SENDING frame, the stream send-side is complete,
    // but the stream is still writable.
    let stream = map.get(5).unwrap();
    assert_eq!(stream.send.is_complete(), true);
    assert!(map.writable.contains(&5));
    assert_eq!(stream.send.error, Some(7));
    assert!(stream.send.is_stopped());
    assert_eq!(stream.send.capacity(), Err(Error::StreamStopped(7)));

    assert_eq!(map.on_stop_sending_frame_received(5, 0), Ok(()));

    // 5. Receive a STOP_SENDING frame for a stream which has been closed.
    // Shutdown the stream abruptly, it should be ok.
    let stream = map.get_or_create(25, false).unwrap();
    assert_eq!(stream.send.shutdown(), Ok((0, 0)));
    // Here we call `write` to make sure the stream's fin_off is set.
    assert_eq!(stream.recv.write(0, Bytes::new(), true), Ok(()));
    assert!(stream.recv.shutdown().is_ok());
    assert_eq!(stream.is_complete(), true);
    map.mark_closed(25, false);
    assert!(
        map.on_stop_sending_frame_received(25, 0).is_ok(),
        "Stream is already closed, just ignore the frame."
    );
}

// Test StreamMap::on_stream_frame_received
#[test]
fn stream_map_on_stream_frame_received() {
    let local_tp = StreamTransportParams {
        initial_max_data: 100,
        initial_max_stream_data_bidi_local: 50,
        initial_max_stream_data_bidi_remote: 50,
        initial_max_stream_data_uni: 50,
        initial_max_streams_bidi: 10,
        initial_max_streams_uni: 5,
    };
    let mut map = StreamMap::new(true, 50, 50, local_tp);

    // 1. Receive a STREAM frame for a local initiated sent-only stream
    let stream_id = 3;
    assert!(is_local(stream_id, true));
    assert!(!is_bidi(stream_id));
    assert_eq!(
        map.on_stream_frame_received(stream_id, 0, 0, false, Bytes::from_static(b"Everything")),
        Err(Error::StreamStateError)
    );

    // 2. Receive a STREAM frame for a local initiated stream that has not yet been created
    let stream_id = 1;
    assert!(is_local(stream_id, true));
    assert!(is_bidi(stream_id));
    assert_eq!(
        map.on_stream_frame_received(stream_id, 0, 0, false, Bytes::from_static(b"Everything")),
        Err(Error::StreamStateError)
    );

    // 3. Peer open too many streams
    //    get_or_create will return Error::StreamLimitError
    assert_eq!(
        map.on_stream_frame_received(40, 0, 10, false, Bytes::from_static(b"Everything")),
        Err(Error::StreamLimitError)
    );

    // 4. Peer send too much data, exceed the connection-level flow control limit
    assert_eq!(
        map.on_stream_frame_received(0, 100, 10, false, Bytes::from_static(b"Everything")),
        Err(Error::FlowControlError)
    );

    // 5. Receive multi unorder STREAM frames for a stream
    // Receive the first block of data of stream 4
    assert_eq!(
        map.on_stream_frame_received(4, 0, 10, false, Bytes::from_static(b"Everything")),
        Ok(())
    );
    // Stream 4 should be created and readable.
    assert!(map.get(4).is_some());
    assert!(map.readable.contains(&4));
    assert_eq!(map.max_recv_off(), 10);
    // Receive the third block of data of stream 4
    assert_eq!(
        map.on_stream_frame_received(4, 14, 4, true, Bytes::from_static(b"QUIC")),
        Ok(())
    );
    assert_eq!(map.max_recv_off(), 18);
    // Receive the second block of data of stream 4
    assert_eq!(
        map.on_stream_frame_received(4, 10, 4, false, Bytes::from_static(b"Over")),
        Ok(())
    );
    assert_eq!(map.max_recv_off(), 18);

    let mut buf = vec![0; 18];
    assert_eq!(
        map.get_mut(4).unwrap().recv.read(&mut buf[0..10]),
        Ok((10, false))
    );
    assert_eq!(buf[0..10], b"Everything"[..]);
    assert_eq!(
        map.get_mut(4).unwrap().recv.read(&mut buf[10..18]),
        Ok((8, true))
    );
    assert_eq!(buf[10..18], b"OverQUIC"[..]);

    // 6. Receive multi overlap STREAM frames for a stream
    // Receive the first block of data of stream 8
    assert_eq!(
        map.on_stream_frame_received(8, 0, 10, false, Bytes::from_static(b"Everything")),
        Ok(())
    );
    assert_eq!(map.max_recv_off(), 28);
    // Duplicate receive the first block of data of stream 8
    assert_eq!(
        map.on_stream_frame_received(8, 0, 10, false, Bytes::from_static(b"Everything")),
        Ok(())
    );
    assert_eq!(map.max_recv_off(), 28);
    // Receive the fifth block of data of stream 8
    assert_eq!(
        map.on_stream_frame_received(8, 14, 4, true, Bytes::from_static(b"QUIC")),
        Ok(())
    );
    assert_eq!(map.max_recv_off(), 36);
    // Receive the second block of data of stream 8, overlap with the first block
    assert_eq!(
        map.on_stream_frame_received(8, 5, 6, false, Bytes::from_static(b"thingO")),
        Ok(())
    );
    assert_eq!(map.max_recv_off(), 36);
    // Receive the fourth block of data of stream 8, overlap with the fifth block
    assert_eq!(
        map.on_stream_frame_received(8, 13, 3, false, Bytes::from_static(b"rQU")),
        Ok(())
    );
    assert_eq!(map.max_recv_off(), 36);
    // Receive the third block of data of stream 8, overlap with the second and fourth block
    assert_eq!(
        map.on_stream_frame_received(8, 11, 4, false, Bytes::from_static(b"verQ")),
        Ok(())
    );
    assert_eq!(map.max_recv_off(), 36);

    let mut buf = vec![0; 18];
    assert_eq!(
        map.get_mut(8).unwrap().recv.read(&mut buf[0..10]),
        Ok((10, false))
    );
    assert_eq!(buf[0..10], b"Everything"[..]);
    assert_eq!(
        map.get_mut(8).unwrap().recv.read(&mut buf[10..18]),
        Ok((8, true))
    );
    assert_eq!(buf[10..18], b"OverQUIC"[..]);
}

fn stream_frame_received_on_closed_stream(map: &mut StreamMap, stream_id: u64) {
    // Create stream.
    let is_local = is_local(stream_id, map.is_server);
    let is_bidi = is_bidi(stream_id);
    let stream = map.get_or_create(stream_id, is_local).unwrap();

    // Fake close the stream.
    if is_bidi {
        assert!(stream.send.shutdown().is_ok());
    }
    assert!(stream.recv.write(0, Bytes::new(), true).is_ok());
    assert!(stream.recv.shutdown().is_ok());
    assert!(stream.is_complete());
    map.mark_closed(stream_id, is_local);

    // Receive stream frame on the closed stream.
    assert!(
        map.on_stream_frame_received(stream_id, 0, 10, false, Bytes::from_static(b"Everything"))
            .is_ok(),
        "Stream is already closed, just ignore the frame."
    );
}

// Test StreamMap::on_stream_frame_received, closed stream case.
#[test]
fn stream_map_on_stream_frame_received_with_closed_stream() {
    // Create stream map.
    let local_tp = StreamTransportParams {
        initial_max_streams_bidi: 5,
        initial_max_streams_uni: 5,
        ..StreamTransportParams::default()
    };
    let peer_tp = StreamTransportParams {
        initial_max_streams_bidi: 10,
        initial_max_streams_uni: 5,
        ..StreamTransportParams::default()
    };
    let mut map = StreamMap::new(true, 50, 50, local_tp);
    map.update_peer_stream_transport_params(peer_tp);

    // Remote bidi stream.
    stream_frame_received_on_closed_stream(&mut map, 0);
    // Remote uni stream.
    stream_frame_received_on_closed_stream(&mut map, 2);
    // Local bidi stream.
    stream_frame_received_on_closed_stream(&mut map, 1);
}

#[test]
fn receive_stream_frame_while_draining() {
    let local_tp = StreamTransportParams {
        initial_max_data: 20,
        initial_max_stream_data_bidi_local: 20,
        initial_max_stream_data_bidi_remote: 20,
        initial_max_stream_data_uni: 50,
        initial_max_streams_bidi: 10,
        initial_max_streams_uni: 5,
    };
    let mut map = StreamMap::new(true, 50, 50, local_tp);
    assert_eq!(map.flow_control.window(), 20);
    assert_eq!(map.flow_control.max_data(), 20);

    // Create stream 4
    let stream = map.get_or_create(4, false).unwrap();
    assert!(stream.recv.shutdown().is_ok());
    assert_eq!(stream.is_draining(), true);

    // Receive the first block of data of stream 4,  should not update max_data
    assert_eq!(
        map.on_stream_frame_received(4, 0, 4, false, Bytes::from_static(b"QUIC")),
        Ok(())
    );
    // map.flow_control.consumed = 4
    assert!(
        !map.flow_control.should_send_max_data(),
        "available_window = 16 > 10 = window/2, not update max_data"
    );
    assert!(!map.rx_almost_full);

    // Receive the second block of data of stream 4, should update max_data
    assert_eq!(
        map.on_stream_frame_received(4, 4, 8, false, Bytes::from_static(b"QUICQUIC")),
        Ok(())
    );
    // map.flow_control.consumed = 12
    assert!(
        map.flow_control.should_send_max_data(),
        "available_window = 8 < 10 = window/2, update max_data"
    );
    assert!(map.rx_almost_full);
}

// Test StreamMap::on_stream_frame_acked
#[test]
fn stream_map_on_stream_frame_acked() {
    let local_tp = StreamTransportParams {
        initial_max_data: 100,
        initial_max_stream_data_bidi_local: 50,
        initial_max_stream_data_bidi_remote: 50,
        initial_max_stream_data_uni: 50,
        initial_max_streams_bidi: 10,
        initial_max_streams_uni: 5,
    };
    let peer_tp = StreamTransportParams {
        initial_max_data: 100,
        initial_max_stream_data_bidi_local: 50,
        initial_max_stream_data_bidi_remote: 50,
        initial_max_stream_data_uni: 50,
        initial_max_streams_bidi: 10,
        initial_max_streams_uni: 5,
    };

    let mut map = StreamMap::new(true, 50, 50, local_tp);
    map.update_peer_stream_transport_params(peer_tp);

    // Create a new client initiated bidirectional stream
    let stream = map.get_or_create(0, false).unwrap();
    assert_eq!(
        stream.send.write(Bytes::from_static(b"Everything"), false),
        Ok(10)
    );
    assert_eq!(stream.send.write(Bytes::from_static(b"Over"), false), Ok(4));
    assert_eq!(stream.send.write(Bytes::from_static(b"QUIC"), true), Ok(4));

    // Ack the first block of data of stream 0
    map.on_stream_frame_acked(0, 0, 10);
    let stream = map.get(0).unwrap();
    assert_eq!(stream.send.ack_off(), 10);
    assert_eq!(stream.send.unacked_len, 8);
    // Ack the third block of data of stream 0
    map.on_stream_frame_acked(0, 14, 4);
    let stream = map.get(0).unwrap();
    assert_eq!(stream.send.ack_off(), 10);
    assert_eq!(stream.send.unacked_len, 8);
    assert!(!stream.send.is_complete());
    // Ack the second block of data of stream 0
    map.on_stream_frame_acked(0, 10, 4);
    let stream = map.get_mut(0).unwrap();
    assert_eq!(stream.send.ack_off(), 18);
    assert_eq!(stream.send.unacked_len, 0);
    // All stream data has been acked, the stream's send-side should be complete.
    assert!(stream.send.is_complete());

    // Here we call `recv.write` to make sure the stream's fin_off is set.
    assert_eq!(stream.recv.write(0, Bytes::new(), true), Ok(()));
    assert!(stream.recv.is_fin());

    // Stream is complete, but it still readable(read fin).
    assert_eq!(stream.is_complete(), true);
    assert!(stream.is_readable());

    // After shutdown the stream receive-side, it should be not readable.
    assert!(stream.recv.shutdown().is_ok());
    assert!(!stream.is_readable());

    // When the stream is complete, but not yet closed, if we receive a new
    // ACK for the stream, it should be closed.
    assert!(!map.is_closed(0));
    map.on_stream_frame_acked(0, 10, 4);
    assert!(map.is_closed(0));

    // Receive an ACK frame for a stream which has been closed, do nothing.
    map.on_stream_frame_acked(0, 10, 4);
}

// Test StreamMap::on_reset_stream_frame_acked
#[test]
fn stream_map_on_reset_stream_frame_acked() {
    let local_tp = StreamTransportParams {
        initial_max_data: 100,
        initial_max_stream_data_bidi_local: 50,
        initial_max_stream_data_bidi_remote: 50,
        initial_max_stream_data_uni: 50,
        initial_max_streams_bidi: 10,
        initial_max_streams_uni: 5,
    };
    let mut map = StreamMap::new(true, 50, 50, local_tp);

    let stream = map.get_or_create(4, false).unwrap();
    assert_eq!(stream.send.shutdown(), Ok((0, 0)));
    assert!(stream.send.is_complete());
    map.on_reset_stream_frame_acked(4);

    // Receive an ACK for a RESET_STREAM frame, no effect on the stream receive-side.
    // The stream is still not complete because the stream receive-side is not complete.
    let stream = map.get_mut(4).unwrap();
    assert!(!stream.is_complete());

    // Here we call `recv.write` to make sure the stream's fin_off is set.
    assert_eq!(stream.recv.write(0, Bytes::new(), true), Ok(()));
    assert!(stream.recv.is_fin());

    // Stream is complete, but it still readable(read fin).
    assert_eq!(stream.is_complete(), true);
    assert!(stream.is_readable());

    // After shutdown the stream receive-side, it should be not readable.
    assert!(stream.recv.shutdown().is_ok());
    assert!(!stream.is_readable());

    // When the stream is complete, but not yet closed, if we receive a new
    // ACK for a RESET_STREAM frame, it should be closed.
    assert!(!map.is_closed(4));
    map.on_reset_stream_frame_acked(4);
    assert!(map.is_closed(4));

    // Receive an ACK for a RESET_STREAM frame which has been closed, do nothing.
    map.on_reset_stream_frame_acked(4);
}

// Test StreamMap::on_stream_frame_lost
#[test]
fn stream_map_on_stream_frame_lost() {
    let local_tp = StreamTransportParams {
        initial_max_data: 100,
        initial_max_stream_data_bidi_local: 50,
        initial_max_stream_data_bidi_remote: 50,
        initial_max_stream_data_uni: 50,
        initial_max_streams_bidi: 10,
        initial_max_streams_uni: 5,
    };
    let peer_tp = StreamTransportParams {
        initial_max_data: 100,
        initial_max_stream_data_bidi_local: 50,
        initial_max_stream_data_bidi_remote: 50,
        initial_max_stream_data_uni: 50,
        initial_max_streams_bidi: 10,
        initial_max_streams_uni: 5,
    };

    let mut map = StreamMap::new(true, 50, 50, local_tp);
    map.update_peer_stream_transport_params(peer_tp);

    // Create a new client initiated bidirectional stream
    let stream = map.get_or_create(0, false).unwrap();
    assert_eq!(
        stream.send.write(Bytes::from_static(b"Everything"), false),
        Ok(10)
    );
    assert_eq!(stream.send.write(Bytes::from_static(b"Over"), false), Ok(4));
    assert_eq!(stream.send.write(Bytes::from_static(b"QUIC"), true), Ok(4));

    // Send all data of stream 0
    let mut out_buf = [0; 18];
    assert_eq!(stream.send.read(&mut out_buf), Ok((18, true)));
    assert!(!stream.is_sendable());

    // Lost the first and third block of data of stream 0
    assert!(map.peek_sendable().is_none());
    map.on_stream_frame_lost(0, 0, 10, false);
    let stream = map.get(0).unwrap();
    assert!(stream.is_sendable());
    assert_eq!(map.peek_sendable(), Some(0));
    map.on_stream_frame_lost(0, 14, 4, true);

    // Retransmit the first block of data of stream 0
    let stream = map.get_mut(0).unwrap();
    let mut out_buf = [0; 18];
    assert_eq!(stream.send.read(&mut out_buf), Ok((10, false)));
    assert!(stream.is_sendable());
    // Retransmit the third block of data of stream 0
    assert_eq!(stream.send.read(&mut out_buf[14..]), Ok((4, true)));
    assert!(!stream.is_sendable());
    map.remove_sendable();

    // Lost empty data with fin
    assert!(map.peek_sendable().is_none());
    map.on_stream_frame_lost(0, 18, 0, true);
    assert_eq!(map.peek_sendable(), Some(0));

    // Retransmit empty data with fin
    let stream = map.get_mut(0).unwrap();
    let mut out_buf = [0; 18];
    assert_eq!(stream.send.read(&mut out_buf), Ok((0, true)));

    // Ack all data of stream 0, the stream's send-side should be complete.
    map.on_stream_frame_acked(0, 0, 18);
    let stream = map.get_mut(0).unwrap();
    assert!(stream.send.is_complete());

    // Here we call `recv.write` to make sure the stream's fin_off is set.
    assert_eq!(stream.recv.write(0, Bytes::new(), true), Ok(()));
    assert!(stream.recv.is_fin());
    assert!(stream.recv.shutdown().is_ok());
    assert_eq!(stream.is_complete(), true);
    map.mark_closed(0, false);
    assert!(map.is_closed(0));

    // After stream 0 is closed, ignore lost event.
    map.on_stream_frame_lost(0, 18, 0, true);
}

// Test StreamMap::on_reset_stream_frame_lost
#[test]
fn stream_map_on_reset_stream_frame_lost() {
    let local_tp = StreamTransportParams {
        initial_max_streams_bidi: 10,
        initial_max_streams_uni: 5,
        ..StreamTransportParams::default()
    };
    let mut map = StreamMap::new(true, 50, 50, local_tp);

    // Found RESET_STREAM frame lost event on a client initiated bidirectional stream
    let stream = map.get_or_create(0, false).unwrap();
    map.on_reset_stream_frame_lost(0, 7, 10);
    let v = map.reset().map(|(&k, &v)| (k, v)).collect::<Vec<_>>();
    assert_eq!(v, [(0, (7, 10))]);

    // Found RESET_STREAM frame lost event on a closed(4, simulation, not true) stream
    map.on_reset_stream_frame_lost(4, 7, 10);
    let v = map.reset().map(|(&k, &v)| (k, v)).collect::<Vec<_>>();
    assert_eq!(v, [(0, (7, 10))]);
}

// Test StreamMap::on_stop_sending_frame_lost
#[test]
fn stream_map_on_stop_sending_frame_lost() {
    let local_tp = StreamTransportParams {
        initial_max_streams_bidi: 10,
        initial_max_streams_uni: 5,
        ..StreamTransportParams::default()
    };
    let mut map = StreamMap::new(true, 50, 50, local_tp);

    // Found STOP_SENDING frame lost event on a client initiated bidirectional stream
    // and the fin flag of the stream receive-side is not set
    let stream = map.get_or_create(0, false).unwrap();
    map.on_stop_sending_frame_lost(0, 7);
    let v = map.stopped().map(|(&k, &v)| (k, v)).collect::<Vec<_>>();
    assert_eq!(v, [(0, 7)]);

    // Found STOP_SENDING frame lost event on a client initiated bidirectional stream
    // and the fin flag of the stream receive-side has been set
    let stream = map.get_or_create(4, false).unwrap();
    assert_eq!(stream.recv.write(0, Bytes::new(), true), Ok(()));
    map.on_stop_sending_frame_lost(4, 7);
    let v = map.stopped().map(|(&k, &v)| (k, v)).collect::<Vec<_>>();
    assert_eq!(v, [(0, 7)]);

    // Found STOP_SENDING frame lost event on a closed(8, simulation, not true) stream
    map.on_stop_sending_frame_lost(8, 7);
    let v = map.stopped().map(|(&k, &v)| (k, v)).collect::<Vec<_>>();
    assert_eq!(v, [(0, 7)]);
}

// Test StreamMap::on_max_stream_data_frame_lost
#[test]
fn stream_map_on_max_stream_data_frame_lost() {
    let local_tp = StreamTransportParams {
        initial_max_streams_bidi: 10,
        initial_max_streams_uni: 5,
        ..StreamTransportParams::default()
    };
    let mut map = StreamMap::new(true, 50, 50, local_tp);

    // Found MAX_STREAM_DATA frame lost event on a client initiated bidirectional stream
    let stream = map.get_or_create(0, false).unwrap();
    map.on_max_stream_data_frame_lost(0);
    assert_eq!(map.almost_full().collect::<Vec<u64>>(), vec![0]);

    // Found RESET_STREAM frame lost event on a closed(4, simulation, not true) stream
    map.on_max_stream_data_frame_lost(4);
    assert_eq!(map.almost_full().collect::<Vec<u64>>(), vec![0]);
}

// Test StreamMap::on_max_data_frame_lost
#[test]
fn stream_map_on_max_data_frame_lost() {
    let mut map: StreamMap = StreamMap::new(true, 50, 50, StreamTransportParams::default());
    assert!(!map.rx_almost_full);
    map.on_max_data_frame_lost();
    assert!(map.rx_almost_full);
}

// Test StreamMap::on_stream_data_blocked_frame_lost
#[test]
fn stream_map_on_stream_data_blocked_frame_lost() {
    let max_data = 100;
    let peer_tp = StreamTransportParams {
        initial_max_streams_bidi: 1,
        initial_max_stream_data_bidi_remote: max_data,
        ..StreamTransportParams::default()
    };

    // Create a client StreamMap and create a stream(0) on it
    let mut map = StreamMap::new(false, 50, 50, StreamTransportParams::default());
    map.update_peer_stream_transport_params(peer_tp);
    assert!(map.get_or_create(0, true).is_ok());
    assert_eq!(map.get(0).unwrap().send.max_data, max_data);

    // 1. Found STREAM_DATA_BLOCKED frame lost event, but the max_stream_data has been updated
    map.on_stream_data_blocked_frame_lost(0, max_data - 1);
    assert!(map.data_blocked.is_empty());

    // 2. Found STREAM_DATA_BLOCKED frame lost event, and the max_stream_data has not been updated
    map.on_stream_data_blocked_frame_lost(0, max_data);
    assert_eq!(map.data_blocked.contains_key(&0), true);
    assert_eq!(map.data_blocked.get(&0), Some(&max_data));

    // 3. Found Found STREAM_DATA_BLOCKED frame lost event on a closed stream
    map.mark_blocked(0, false, 0);
    map.mark_closed(0, true);
    map.on_stream_data_blocked_frame_lost(0, max_data);
    assert!(map.data_blocked.is_empty());
}

// Test StreamMap::on_data_blocked_frame_lost
#[test]
fn stream_map_on_data_blocked_frame_lost() {
    let max_data = 100;
    let peer_tp = StreamTransportParams {
        initial_max_data: max_data,
        ..StreamTransportParams::default()
    };
    let mut map = StreamMap::new(true, 50, 50, StreamTransportParams::default());
    map.update_peer_stream_transport_params(peer_tp);

    // 1. Found DATA_BLOCKED frame lost event, but the max_data has been updated
    map.on_data_blocked_frame_lost(max_data - 1);
    assert_eq!(map.data_blocked_at(), None);

    // 2. Found DATA_BLOCKED frame lost event, and the max_data has not been updated
    map.on_data_blocked_frame_lost(max_data);
    assert_eq!(map.data_blocked_at(), Some(max_data));

    // 3. Received MAX_DATA frame, and the max_data is larger than the data_blocked_at
    map.on_max_data_frame_received(max_data + 1);
    assert_eq!(map.data_blocked_at(), None);
}

// Test StreamMap::{streams_blocked, streams_blocked_at}
#[test]
fn stream_map_streams_blocked() {
    // Create a client StreamMap
    let is_server = false;
    let mut map = StreamMap::new(is_server, 50, 50, StreamTransportParams::default());

    for stream_id in [0, 2] {
        assert_eq!(
            map.get_or_create(stream_id, is_local(stream_id, is_server))
                .err(),
            Some(Error::StreamLimitError)
        );
        assert_eq!(map.streams_blocked(), true);
        assert_eq!(
            map.streams_blocked_at(is_bidi(stream_id)),
            Some(map.concurrency_control.peer_max_streams(is_bidi(stream_id)))
        );

        assert!(map
            .on_max_streams_frame_received(1, is_bidi(stream_id))
            .is_ok());
        assert!(map.streams_blocked_at(is_bidi(stream_id)).is_none());
        assert!(map
            .get_or_create(stream_id, is_local(stream_id, is_server))
            .is_ok());
    }
}

// Test StreamMap::on_streams_blocked_frame_lost
#[test]
fn stream_map_on_streams_blocked_frame_lost() {
    let peer_tp = StreamTransportParams {
        initial_max_streams_bidi: 10,
        initial_max_streams_uni: 5,
        ..StreamTransportParams::default()
    };

    // Create a client StreamMap
    let is_server = false;
    let mut map = StreamMap::new(is_server, 50, 50, StreamTransportParams::default());
    map.update_peer_stream_transport_params(peer_tp);

    for bidi in &[true, false] {
        map.on_streams_blocked_frame_lost(*bidi, 1);
        assert_eq!(map.streams_blocked_at(*bidi), None);
        map.on_streams_blocked_frame_lost(*bidi, map.concurrency_control.peer_max_streams(*bidi));
        assert_eq!(
            map.streams_blocked_at(*bidi),
            Some(map.concurrency_control.peer_max_streams(*bidi))
        );
    }
}

// Test StreamMap::update_peer_stream_transport_params
#[test]
fn stream_map_update_peer_stream_transport_params() {
    let mut map = StreamMap::new(true, 50, 50, StreamTransportParams::default());
    assert_eq!(map.peer_transport_params, StreamTransportParams::default());

    let tp = StreamTransportParams {
        initial_max_data: 100,
        initial_max_stream_data_bidi_local: 10,
        initial_max_stream_data_bidi_remote: 11,
        initial_max_stream_data_uni: 12,
        initial_max_streams_bidi: 13,
        initial_max_streams_uni: 14,
    };

    // Update peer transport params
    map.update_peer_stream_transport_params(tp.clone());
    assert_eq!(map.peer_transport_params, tp);
}

// Stream unit tests
// Test Stream::new
fn stream_new() {
    let stream = Stream::new(true, true, 20, 30, DEFAULT_STREAM_WINDOW);

    assert!(stream.local, "send-side is local");
    assert!(stream.bidi, "send-side is bidi");
    assert!(stream.incremental, "send-side is incremental");
    assert_eq!(stream.urgency, 127);
    assert_eq!(stream.write_thresh, 1);
    assert_eq!(stream.recv.max_data(), 30);
    assert_eq!(stream.send.max_data(), 20);
}

// Test Stream::is_complete
#[test]
fn stream_bidi_complete() {
    // Note that peer initiated stream unit tests are same as local initiated stream,
    // we would not write unit tests for them.

    // Create a local bidi stream
    let mut stream = Stream::new(true, true, 30, 30, DEFAULT_STREAM_WINDOW);

    // Check initial state
    assert!(!stream.send.is_fin(), "send-side is not fin");
    assert!(!stream.send.is_complete(), "send-side is not complete");
    assert!(!stream.recv.is_fin(), "recv-side is not fin");
    assert!(!stream.recv.is_complete(), "recv-side is not complete");
    assert!(!stream.is_complete(), "stream is not complete");

    // Check stream send-side state after sending data
    assert_eq!(
        stream.send.write(Bytes::from_static(b"Everything"), false),
        Ok(10)
    );
    assert_eq!(
        stream.send.write(Bytes::from_static(b"OverQUIC"), false),
        Ok(8)
    );

    assert!(!stream.send.is_fin());
    assert!(!stream.send.is_complete());

    // Send-side write fin
    assert_eq!(stream.send.write(Bytes::new(), true), Ok(0));

    assert!(stream.send.is_fin(), "send-side write fin");
    assert!(!stream.send.is_complete());

    // Check stream received-side state after receiving data
    assert!(stream
        .recv
        .write(0, Bytes::from_static(b"Everything"), true)
        .is_ok());
    assert!(!stream.recv.is_fin());
    assert!(!stream.recv.is_complete());

    // Check stream send-side state when some data is acked
    stream.send.ack(10, 8);
    assert!(!stream.send.is_complete());

    let mut buf = [0; 5];
    assert_eq!(stream.recv.read(&mut buf), Ok((5, false)));
    assert!(!stream.recv.is_fin());

    stream.send.ack(5, 5);
    assert!(!stream.send.is_complete());

    stream.send.ack(0, 5);
    assert!(
        stream.send.is_complete(),
        "all sent data is acked, send-side is complete"
    );

    assert!(!stream.is_complete());

    let mut buf = [0; 5];
    assert_eq!(stream.recv.read(&mut buf), Ok((5, true)));
    assert!(
        stream.recv.is_fin(),
        "all received data is read, recv-side is fin"
    );
    assert!(
        stream.recv.is_complete(),
        "all received data is read, recv-side is complete"
    );

    assert!(stream.is_complete());
}

#[test]
fn stream_uni_complete() {
    // 1. Local initiated uni stream
    let mut stream = Stream::new(false, true, 30, 30, DEFAULT_STREAM_WINDOW);

    // Check initial state
    assert!(!stream.send.is_fin(), "send-side is not fin");
    assert!(!stream.send.is_complete(), "send-side is not complete");
    assert!(!stream.is_complete(), "stream is not complete");

    // Check stream send-side state after sending data
    assert_eq!(
        stream.send.write(Bytes::from_static(b"Everything"), false),
        Ok(10)
    );
    assert_eq!(
        stream.send.write(Bytes::from_static(b"OverQUIC"), false),
        Ok(8)
    );

    assert!(!stream.send.is_fin());
    assert!(!stream.send.is_complete());

    // Send-side write fin
    assert_eq!(stream.send.write(Bytes::new(), true), Ok(0));

    assert!(stream.send.is_fin(), "send-side write fin");
    assert!(!stream.send.is_complete());

    // Check stream send-side state when some data is acked
    stream.send.ack(10, 8);
    assert!(!stream.send.is_complete());
    assert!(!stream.is_complete());

    stream.send.ack(5, 5);
    assert!(!stream.send.is_complete());
    assert!(!stream.is_complete());

    stream.send.ack(0, 5);
    assert!(
        stream.send.is_complete(),
        "all sent data is acked, send-side is complete"
    );
    assert!(stream.is_complete());

    // 2. Peer initiated uni stream
    let mut stream = Stream::new(false, false, 30, 30, DEFAULT_STREAM_WINDOW);

    // Check initial state
    assert!(!stream.recv.is_fin(), "recv-side is not fin");
    assert!(!stream.recv.is_complete(), "recv-side is not complete");
    assert!(!stream.is_complete(), "stream is not complete");

    // Check stream received-side state after receiving data
    assert!(stream
        .recv
        .write(0, Bytes::from_static(b"Everything"), true)
        .is_ok());
    assert!(!stream.recv.is_fin());
    assert!(!stream.is_complete());

    let mut buf = [0; 5];
    assert_eq!(stream.recv.read(&mut buf), Ok((5, false)));
    assert!(!stream.recv.is_fin());
    assert!(!stream.is_complete());

    let mut buf = [0; 5];
    assert_eq!(stream.recv.read(&mut buf), Ok((5, true)));
    assert!(
        stream.recv.is_fin(),
        "all received data is read, recv-side is fin"
    );
    assert!(
        stream.recv.is_complete(),
        "all received data is read, recv-side is complete"
    );

    assert!(stream.is_complete());
}

#[test]
fn stream_is_readable() {
    // Create a local initiated bidi stream
    let mut stream = Stream::new(true, true, 30, 30, DEFAULT_STREAM_WINDOW);
    assert!(!stream.is_readable(), "no data to read");

    // Receive the first block of data
    assert!(stream
        .recv
        .write(0, Bytes::from_static(b"Everything"), false)
        .is_ok());
    assert!(stream.is_readable());

    // Read first block of data
    let mut buf = [0; 10];
    assert_eq!(stream.recv.read(&mut buf), Ok((10, false)));
    assert!(!stream.is_readable(), "all received data is read");

    // Receive third block of data
    assert!(stream
        .recv
        .write(14, Bytes::from_static(b"QUIC"), true)
        .is_ok());
    assert!(!stream.is_readable(), "unordered data");

    // Receive second block of data
    assert!(stream
        .recv
        .write(10, Bytes::from_static(b"Over"), false)
        .is_ok());
    assert!(stream.is_readable());

    // Read part of the data
    let mut buf = [0; 5];
    assert_eq!(stream.recv.read(&mut buf), Ok((5, false)));
    assert_eq!(&buf, b"OverQ");
    assert!(stream.is_readable());

    // Read all the data
    let mut buf = [0; 3];
    assert_eq!(stream.recv.read(&mut buf), Ok((3, true)));
    assert_eq!(&buf, b"UIC");
    assert!(!stream.is_readable(), "all received data is read");
}

#[test]
fn stream_is_writable() {
    // Create a local initiated bidi stream
    let mut stream = Stream::new(true, true, 10, 30, DEFAULT_STREAM_WINDOW);
    assert!(stream.is_writable(), "stream is writable");
    assert_eq!(stream.send.max_data(), 10);

    // Write the first block of data
    assert_eq!(
        stream.send.write(Bytes::from_static(b"Everything"), false),
        Ok(10)
    );
    assert!(!stream.is_writable(), "stream blocked by flow control");

    // Update flow control limit
    stream.send.update_max_data(20);
    assert_eq!(stream.send.max_data(), 20);
    assert!(stream.is_writable(), "stream is writable");

    // Write second block of data with fin
    assert_eq!(
        stream.send.write(Bytes::from_static(b"OverQUIC"), true),
        Ok(8)
    );
    assert!(stream.send.is_fin(), "send-side write fin");
    assert!(
        !stream.is_writable(),
        "stream is not writable because fin is write"
    );

    // Create a local initiated bidi stream
    let mut stream = Stream::new(true, true, 20, 30, DEFAULT_STREAM_WINDOW);
    assert!(stream.is_writable(), "stream is writable");
    assert_eq!(stream.send.max_data(), 20);

    // Write the first block of data
    assert_eq!(
        stream.send.write(Bytes::from_static(b"Everything"), false),
        Ok(10)
    );

    assert_eq!(stream.send.shutdown(), Ok((0, 10)));
    assert!(
        !stream.is_writable(),
        "stream is not writable because send-side is shutdown"
    );
}

// Test Stream::is_sendable, takes retransmission into account.
#[test]
fn stream_is_sendable() {
    // Create a local initiated bidi stream
    let mut stream = Stream::new(true, true, 20, 30, DEFAULT_STREAM_WINDOW);
    assert!(!stream.is_sendable(), "no data to send");
    assert_eq!(stream.send.max_data(), 20);

    // Write the first block of data
    assert_eq!(
        stream.send.write(Bytes::from_static(b"Everything"), false),
        Ok(10)
    );
    assert!(stream.is_sendable(), "has 10 bytes to send");

    // Send part of the first block data
    let mut buf = [0; 5];
    assert_eq!(stream.send.read(&mut buf), Ok((5, false)));
    assert!(
        stream.is_sendable(),
        "send_off < write_off, has 5 bytes to send"
    );

    // Send all the first block data
    let mut buf = [0; 5];
    assert_eq!(stream.send.read(&mut buf), Ok((5, false)));
    assert!(!stream.is_sendable(), "all buffered data is sent");

    // Write the second block of data
    assert_eq!(
        stream.send.write(Bytes::from_static(b"OverQUIC"), true),
        Ok(8)
    );
    assert!(stream.is_sendable(), "has 8 bytes to send");

    // Send all the second block data
    let mut buf = [0; 8];
    assert_eq!(stream.send.read(&mut buf), Ok((8, true)));
    assert!(!stream.is_sendable(), "all buffered data is sent");

    // Ack part of the second block data: [15, 18)
    stream.send.ack_and_drop(15, 3);

    // Lost part of the first block of data and need to retransmit
    stream.send.retransmit(5, 10);
    assert!(stream.is_sendable(), "has 10 bytes to retransmit");
    let mut buf = [0; 10];
    assert_eq!(stream.send.read(&mut buf), Ok((10, false)));
    assert_eq!(buf, b"thingOverQ"[..]);
    assert!(!stream.is_sendable(), "all buffered data is sent");

    // Lost part of the first block of data and need to retransmit
    stream.send.retransmit(0, 5);
    assert!(stream.is_sendable(), "has 5 bytes to retransmit");
    let mut buf = [0; 5];
    assert_eq!(stream.send.read(&mut buf), Ok((5, false)));
    assert_eq!(buf, b"Every"[..]);
    assert!(!stream.is_sendable(), "all buffered data is sent");

    // All data is sent and acked
    stream.send.ack_and_drop(0, 15);
    assert!(!stream.is_sendable(), "all data is sent and acked");
    assert!(stream.send.is_complete(), "all data is sent and acked");
}

// Test Stream::is_draining, takes unacked data into account.
#[test]
fn stream_is_draining() {
    // Create a local initiated bidi stream
    let mut stream = Stream::new(true, true, 20, 30, DEFAULT_STREAM_WINDOW);
    assert!(!stream.is_draining(), "the stream's recv-side is open");

    // Receive the first block of data
    assert!(stream
        .recv
        .write(0, Bytes::from_static(b"Everything"), false)
        .is_ok());
    assert!(stream.is_readable());

    // Receive the third block of data, unorderly
    assert!(stream
        .recv
        .write(14, Bytes::from_static(b"QUIC"), true)
        .is_ok());
    assert_eq!(stream.recv.recv_off(), 18);

    // Read part of the first block data
    let mut buf = [0; 5];
    assert_eq!(stream.recv.read(&mut buf), Ok((5, false)));
    assert_eq!(buf, b"Every"[..]);
    assert_eq!(stream.recv.read_off(), 5);

    // Shutdown the stream's recv-side
    assert!(stream.recv.shutdown().is_ok());
    assert_eq!(stream.recv.read_off(), stream.recv.recv_off());
    assert!(stream.is_draining(), "the stream's recv-side is shutdown");
    assert!(!stream.is_readable(), "the stream's recv-side is shutdown");

    // Receive second block of data, which will be discarded
    assert!(stream
        .recv
        .write(10, Bytes::from_static(b"Over"), false)
        .is_ok());
    assert!(stream.is_draining(), "the stream's recv-side is shutdown");
    assert!(!stream.is_readable(), "the stream's recv-side is shutdown");
}

// ConcurrencyControl unit tests
// Test ConcurrencyControl::new
#[test]
fn concurrency_control_new() {
    let cc = ConcurrencyControl::new(10, 3);

    let mut peer_bidi_avail_ids = ranges::RangeSet::default();
    peer_bidi_avail_ids.insert(0..10);
    let mut peer_uni_avail_ids = ranges::RangeSet::default();
    peer_uni_avail_ids.insert(0..3);
    assert_eq!(
        cc,
        ConcurrencyControl {
            local_max_streams_bidi: 10,
            local_max_streams_bidi_next: 10,
            local_max_streams_uni: 3,
            local_max_streams_uni_next: 3,
            local_opened_streams_bidi: 0,
            local_opened_streams_uni: 0,
            peer_max_streams_bidi: 0,
            peer_max_streams_uni: 0,
            peer_opened_streams_bidi: 0,
            peer_opened_streams_uni: 0,
            streams_blocked_at_bidi: None,
            streams_blocked_at_uni: None,
            peer_bidi_avail_ids,
            peer_uni_avail_ids,
            ..ConcurrencyControl::default()
        }
    );
}

// Test ConcurrencyControl::check_concurrency_limits
#[test]
fn concurrency_control_check_concurrency_limits() {
    let mut cc = ConcurrencyControl::new(20, 12);
    cc.update_peer_max_streams(true, 10);
    cc.update_peer_max_streams(false, 6);

    assert_eq!(cc.local_max_streams_bidi, 20);
    assert_eq!(cc.local_max_streams_uni, 12);
    assert_eq!(cc.peer_max_streams_bidi, 10);
    assert_eq!(cc.peer_max_streams_uni, 6);

    // 1. Test is_server = true, i.e. current endpoint is server

    // 1.1 Server initiated bidirectional stream
    // (stream_id & 0x01 == 1 && stream_id & 0x02 == 0), 1, 5, 9...
    // is_server = true, is_local = true, is_bidi = true
    for (stream_id, is_server, result, local_opened_streams_bidi) in vec![
        (5, true, Ok(()), 2),
        // Open stream in order
        (9, true, Ok(()), 3),
        // Open stream unordered
        (1, true, Ok(()), 3),
        // Local opened bidi stream over peer_max_streams_bidi limit
        (41, true, Err(Error::StreamLimitError), 3),
    ] {
        assert_eq!(cc.check_concurrency_limits(stream_id, is_server), result);
        assert_eq!(cc.local_opened_streams_bidi, local_opened_streams_bidi);
    }

    // 1.2 Server initiated unidirectional stream
    // (stream_id & 0x01 == 1 && stream_id & 0x02 == 1), 3, 7, 11...
    // is_server = true, is_local = true, is_bidi = false
    for (stream_id, is_server, result, local_opened_streams_uni) in vec![
        (7, true, Ok(()), 2),
        // Open stream in order
        (11, true, Ok(()), 3),
        // Open stream unordered
        (3, true, Ok(()), 3),
        // Local opened uni stream over peer_max_streams_uni limit
        (27, true, Err(Error::StreamLimitError), 3),
    ] {
        assert_eq!(cc.check_concurrency_limits(stream_id, is_server), result);
        assert_eq!(cc.local_opened_streams_uni, local_opened_streams_uni);
    }

    // 1.3 Client initiated bidirectional stream
    // (stream_id & 0x01 == 0 && stream_id & 0x02 == 0), 0, 4, 8...
    // is_server = true, is_local = false, is_bidi = true
    for (stream_id, is_server, result, peer_opened_streams_bidi) in vec![
        (4, true, Ok(()), 2),
        // Open stream in order
        (8, true, Ok(()), 3),
        // Open stream unordered
        (0, true, Ok(()), 3),
        // Peer opened bidi stream over local_max_streams_bidi limit
        (80, true, Err(Error::StreamLimitError), 3),
    ] {
        assert_eq!(cc.check_concurrency_limits(stream_id, is_server), result);
        assert_eq!(cc.peer_opened_streams_bidi, peer_opened_streams_bidi);
    }

    // 1.4 Client initiated unidirectional stream
    // (stream_id & 0x01 == 0 && stream_id & 0x02 == 1), 2, 6, 10...
    // is_server = true, is_local = false, is_bidi = false
    for (stream_id, is_server, result, peer_opened_streams_uni) in vec![
        (6, true, Ok(()), 2),
        // Open stream in order
        (10, true, Ok(()), 3),
        // Open stream unordered
        (2, true, Ok(()), 3),
        // Peer opened uni stream over local_max_streams_uni limit
        (50, true, Err(Error::StreamLimitError), 3),
    ] {
        assert_eq!(cc.check_concurrency_limits(stream_id, is_server), result);
        assert_eq!(cc.peer_opened_streams_uni, peer_opened_streams_uni);
    }

    // 2. Test is_server = false, i.e. current endpoint is client
    let mut cc = ConcurrencyControl::new(20, 12);
    cc.update_peer_max_streams(true, 10);
    cc.update_peer_max_streams(false, 6);

    assert_eq!(cc.local_max_streams_bidi, 20);
    assert_eq!(cc.local_max_streams_uni, 12);
    assert_eq!(cc.peer_max_streams_bidi, 10);
    assert_eq!(cc.peer_max_streams_uni, 6);

    // 2.1 Server initiated bidirectional stream
    // (stream_id & 0x01 == 1 && stream_id & 0x02 == 0), 1, 5, 9...
    // is_server = false, is_local = false, is_bidi = true
    assert_eq!(cc.check_concurrency_limits(5, false), Ok(()));
    assert_eq!(cc.peer_opened_streams_bidi, 2);
    // Open stream in order
    assert_eq!(cc.check_concurrency_limits(9, false), Ok(()));
    assert_eq!(cc.peer_opened_streams_bidi, 3);
    // Open stream unordered
    assert_eq!(cc.check_concurrency_limits(1, false), Ok(()));
    assert_eq!(cc.peer_opened_streams_bidi, 3);
    // Peer opened bidi stream over local_max_streams_bidi limit
    assert_eq!(
        cc.check_concurrency_limits(81, false),
        Err(Error::StreamLimitError)
    );

    // 2.2 Server initiated unidirectional stream
    // (stream_id & 0x01 == 1 && stream_id & 0x02 == 1), 3, 7, 11...
    // is_server = false, is_local = false, is_bidi = false
    for (stream_id, is_server, result, peer_opened_streams_uni) in vec![
        (7, false, Ok(()), 2),
        // Open stream in order
        (11, false, Ok(()), 3),
        // Open stream unordered
        (3, false, Ok(()), 3),
        // Peer opened uni stream over local_max_streams_uni limit
        (51, false, Err(Error::StreamLimitError), 3),
    ] {
        assert_eq!(cc.check_concurrency_limits(stream_id, is_server), result);
        assert_eq!(cc.peer_opened_streams_uni, peer_opened_streams_uni);
    }

    // 2.3 Client initiated bidirectional stream
    // (stream_id & 0x01 == 0 && stream_id & 0x02 == 0), 0, 4, 8...
    // is_server = false, is_local = true, is_bidi = true
    for (stream_id, is_server, result, local_opened_streams_bidi) in vec![
        (4, false, Ok(()), 2),
        // Open stream in order
        (8, false, Ok(()), 3),
        // Open stream unordered
        (0, false, Ok(()), 3),
        // Local opened bidi stream over peer_max_streams_bidi limit
        (40, false, Err(Error::StreamLimitError), 3),
    ] {
        assert_eq!(cc.check_concurrency_limits(stream_id, is_server), result);
        assert_eq!(cc.local_opened_streams_bidi, local_opened_streams_bidi);
    }

    // 2.4 Client initiated unidirectional stream
    // (stream_id & 0x01 == 0 && stream_id & 0x02 == 1), 2, 6, 10...
    // is_server = false, is_local = true, is_bidi = false
    for (stream_id, is_server, result, local_opened_streams_uni) in vec![
        (6, false, Ok(()), 2),
        // Open stream in order
        (10, false, Ok(()), 3),
        // Open stream unordered
        (2, false, Ok(()), 3),
        // Local opened uni stream over peer_max_streams_uni limit
        (26, false, Err(Error::StreamLimitError), 3),
    ] {
        assert_eq!(cc.check_concurrency_limits(stream_id, is_server), result);
        assert_eq!(cc.local_opened_streams_uni, local_opened_streams_uni);
    }
}

// Test ConcurrencyControl::{
//         should_update_max_streams_bidi,
//         should_update_max_streams_uni,
//         add_max_streams_bidi_credits,
//         add_max_streams_uni_credits,
//         update_peer_max_streams_bidi,
//         update_peer_max_streams_uni,
//         max_streams_bidi_next,
//         max_streams_uni_next,
//         peer_streams_left_bidi,
//         peer_streams_left_uni,
// }
#[test]
fn concurrency_control_update_methods() {
    let mut cc = ConcurrencyControl::new(20, 12);
    cc.update_peer_max_streams(true, 10);
    cc.update_peer_max_streams(false, 6);

    assert_eq!(cc.should_update_local_max_streams(true), false);
    assert_eq!(cc.should_update_local_max_streams(false), false);
    assert_eq!(cc.local_max_streams_bidi_next, 20);
    assert_eq!(cc.local_max_streams_uni_next, 12);
    assert_eq!(cc.peer_streams_left(true), 10);
    assert_eq!(cc.peer_streams_left(false), 6);

    // Peer opened 20 bidi streams
    assert_eq!(cc.check_concurrency_limits(76, true), Ok(()));
    assert_eq!(cc.peer_opened_streams_bidi, 20);
    // Peer opened 12 uni streams
    assert_eq!(cc.check_concurrency_limits(46, true), Ok(()));
    assert_eq!(cc.peer_opened_streams_uni, 12);
    assert_eq!(cc.should_update_local_max_streams(true), false);
    assert_eq!(cc.should_update_local_max_streams(false), false);
    cc.increase_max_streams_credits(true, 11);
    cc.increase_max_streams_credits(false, 7);
    assert_eq!(cc.local_max_streams_bidi_next, 31);
    assert_eq!(cc.local_max_streams_uni_next, 19);
    // Peer opened 20 bidi streams, closed 11(> 20/2), should update
    assert_eq!(cc.should_update_local_max_streams(true), true);
    // Peer opened 12 uni streams, closed 7(>12/2), should update
    assert_eq!(cc.should_update_local_max_streams(false), true);
    cc.update_local_max_streams(true);
    cc.update_local_max_streams(false);
    // After update, should_update_max_streams_bidi should be false
    assert_eq!(cc.should_update_local_max_streams(true), false);
    assert_eq!(cc.should_update_local_max_streams(false), false);
    assert_eq!(cc.local_max_streams_bidi_next, 31);
    assert_eq!(cc.local_max_streams_uni_next, 19);

    // Local opened 2 bidi streams, left 8
    assert_eq!(cc.check_concurrency_limits(5, true), Ok(()));
    assert_eq!(cc.local_opened_streams_bidi, 2);
    // Local opened 2 uni streams, left 4
    assert_eq!(cc.check_concurrency_limits(7, true), Ok(()));
    assert_eq!(cc.local_opened_streams_uni, 2);
    assert_eq!(cc.peer_streams_left(true), 8);
    assert_eq!(cc.peer_streams_left(false), 4);
}

// RecvBuf unit tests
// Test RecvBuf::new
#[test]
fn recv_buf_new() {
    let max_data: u64 = 100;
    let max_window: u64 = 600;
    let recv = RecvBuf::new(100, 600);
    assert_eq!(recv.data.len(), 0);
    assert_eq!(recv.read_off, 0);
    assert_eq!(recv.recv_off, 0);
    assert_eq!(recv.fin_off, None);
    assert_eq!(recv.error, None);
    assert_eq!(recv.shutdown, false);
}

// Write multiple empty FIN buffers to RecvBuf.
#[test]
fn recv_buf_write_multiple_empty_fin_buffer() {
    let mut recv = RecvBuf::new(100, 600);
    assert_eq!(recv.data.len(), 0);

    // recv [0, 10) with FIN
    assert_eq!(
        recv.write(0, Bytes::from_static(b"Everything"), true),
        Ok(())
    );

    for i in 1..5 {
        // Write empty FIN buffer
        assert_eq!(recv.write(10, Bytes::new(), true), Ok(()));
        assert_eq!(recv.data.len(), 1);
        assert_eq!(recv.fin_off, Some(10));
        assert!(recv.ready());
    }
}

// Test RecvBuf::{write, read}
#[test]
fn recv_buf_multi_write_in_order() {
    let mut recv = RecvBuf::new(100, 600);
    assert_eq!(recv.data.len(), 0);

    let data = Bytes::from("Hello, TQUIC!");
    let data_len = data.len();

    let first = Bytes::from("Hell");
    let second = Bytes::from("o, T");
    let third = Bytes::from("QUIC!");

    assert_eq!(recv.write(0, first, false), Ok(()));
    assert_eq!(recv.recv_off, 4);

    assert_eq!(recv.write(4, second, false), Ok(()));
    assert_eq!(recv.recv_off, 8);

    assert_eq!(recv.write(8, third, true), Ok(()));
    assert_eq!(recv.recv_off, 13);

    let mut out_buf = [0; 128];
    let (len, fin) = recv.read(&mut out_buf[..128]).unwrap();
    assert_eq!(len, 13);
    assert_eq!(fin, true);
    assert_eq!(recv.fin_off, Some(13));
    assert_eq!(recv.recv_off, 13);
    assert_eq!(recv.read_off, 13);
    assert_eq!(out_buf[..data_len], data[..data_len]);
}

// Test RecvBuf::{write, read} with out of order data
#[test]
fn recv_buf_multi_write_out_of_order() {
    let mut recv = RecvBuf::new(100, 600);
    assert_eq!(recv.data.len(), 0);

    let data = Bytes::from("Hello, TQUIC!");
    let data_len = data.len();

    let first = Bytes::from("Hell");
    let second = Bytes::from("o, T");
    let third = Bytes::from("QUIC!");

    // recv [4, 8)
    assert_eq!(recv.write(4, second, false), Ok(()));
    assert_eq!(recv.recv_off, 8);
    assert_eq!(recv.read_off, 0);

    // Out of order, read 0 bytes
    let mut out_buf = [0; 128];
    assert_eq!(recv.read(&mut out_buf[..128]), Err(Error::Done));

    // recv [8, 13)
    assert_eq!(recv.write(8, third, true), Ok(()));
    assert_eq!(recv.recv_off, 13);
    assert_eq!(recv.read_off, 0);
    assert_eq!(recv.fin_off, Some(13));

    // Out of order, read 0 bytes
    let mut out_buf = [0; 128];
    assert_eq!(recv.read(&mut out_buf[..128]), Err(Error::Done));

    // recv [0, 4)
    assert_eq!(recv.write(0, first, false), Ok(()));
    assert_eq!(recv.recv_off, 13);
    assert_eq!(recv.fin_off, Some(13));

    // read 13 bytes
    let mut out_buf = [0; 128];
    let (len, fin) = recv.read(&mut out_buf[..128]).unwrap();
    assert_eq!(len, 13);
    assert_eq!(fin, true);
    assert_eq!(recv.fin_off, Some(13));
    assert_eq!(recv.recv_off, 13);
    assert_eq!(recv.read_off, 13);
    assert_eq!(out_buf[..data_len], data[..data_len]);
}

#[test]
fn recv_buf_write_overlapping_data() {
    let mut recv = RecvBuf::new(20, 10);
    assert_eq!(recv.data.len(), 0);

    let data = Bytes::from("EverythingOverQUIC");
    let data_len = data.len();

    // recv [0, 5)
    assert_eq!(recv.write(0, Bytes::from_static(b"Every"), false), Ok(()));

    // consume [0, 5)
    let mut buf = [0; 5];
    assert_eq!(recv.read(&mut buf), Ok((5, false)));
    assert_eq!(buf, data[..5]);

    // recv [0, 10)
    // Bytes up to read_off have already been consumed by application, will be
    // discard directly.
    assert_eq!(
        recv.write(0, Bytes::from_static(b"Everything"), false),
        Ok(())
    );

    // recv [14, 18)
    assert_eq!(recv.write(14, Bytes::from_static(b"QUIC"), true), Ok(()));

    // duplicate recv [5, 10)
    assert_eq!(recv.write(5, Bytes::from_static(b"thing"), false), Ok(()));

    // recv [5, 11), overlap with [0, 10)
    assert_eq!(recv.write(5, Bytes::from_static(b"thingO"), false), Ok(()));

    // recv [13, 16), overlap with [14, 18)
    assert_eq!(recv.write(13, Bytes::from_static(b"rQU"), false), Ok(()));

    // recv [10, 14), overlap with [5, 11) and [13, 16)
    assert_eq!(recv.write(10, Bytes::from_static(b"Over"), false), Ok(()));
    assert_eq!(recv.recv_off, 18);

    let mut buf = [0; 18];
    assert_eq!(recv.read(&mut buf), Ok((13, true)));
    assert_eq!(buf[0..13], data[5..]);
}

#[test]
fn recv_buf_write_exceed_flow_control() {
    let mut recv = RecvBuf::new(10, 5);
    assert_eq!(
        recv.write(0, Bytes::from_static(b"EverythingOverQUIC"), false),
        Err(Error::FlowControlError)
    );
}

#[test]
fn recv_buf_final_size_legality() {
    let mut recv = RecvBuf::new(20, 10);
    // recv [0, 14)
    assert_eq!(
        recv.write(0, Bytes::from_static(b"EverythingOver"), false),
        Ok(())
    );

    // Do nothing if the buffer is empty and without fin flag.
    assert_eq!(recv.write(10, Bytes::new(), false), Ok(()));

    // An endpoint received a STREAM frame containing a final size that was lower than
    // the size of data that was already received.
    assert_eq!(
        recv.write(0, Bytes::from_static(b"Everything"), true),
        Err(Error::FinalSizeError)
    );

    // recv [14, 18)
    assert_eq!(recv.write(14, Bytes::from_static(b"QUIC"), true), Ok(()));

    // A receiver SHOULD treat receipt of data at or beyond the final size as an error
    // of type FINAL_SIZE_ERROR.
    assert_eq!(
        recv.write(18, Bytes::from_static(b"!"), false),
        Err(Error::FinalSizeError)
    );

    // Once a final size for a stream is known, it cannot be change. If a STREAM frame
    // is received indicating a change in the final size for the stream, an endpoint
    // SHOULD respond with an error of type FINAL_SIZE_ERROR.
    assert_eq!(
        recv.write(10, Bytes::from_static(b"Over"), true),
        Err(Error::FinalSizeError)
    );

    // Do nothing if the final offset is already known, an the buffer is empty.
    assert_eq!(recv.write(10, Bytes::new(), false), Ok(()));
}

#[test]
fn recv_buf_read_after_reset() {
    let mut buf = [0; 20];

    // Subcase 1: reset before receiving any data
    let mut recv = RecvBuf::new(20, 10);
    assert_eq!(recv.reset(7, 18), Ok(18));

    assert!(recv.ready());
    assert_eq!(recv.read(&mut buf), Err(Error::StreamReset(7)));
    assert_eq!(recv.read(&mut buf), Err(Error::Done));

    // Subcase 2: reset after receiving some data without fin flag
    let mut recv = RecvBuf::new(20, 10);

    // recv [0, 10), and then reset it at offset 18 with error code 7.
    assert_eq!(
        recv.write(0, Bytes::from_static(b"Everything"), false),
        Ok(())
    );
    assert_eq!(recv.reset(7, 18), Ok(8));

    // The stream has been reset by the peer.
    assert_eq!(recv.read(&mut buf), Err(Error::StreamReset(7)));
    assert_eq!(recv.read(&mut buf), Err(Error::Done));

    // Subcase 3: reset after receiving some data with fin flag
    let mut recv = RecvBuf::new(20, 10);

    // recv [0, 18), and then reset it at offset 18 with error code 7.
    assert_eq!(
        recv.write(0, Bytes::from_static(b"EverythingOverQuic"), true),
        Ok(())
    );
    assert_eq!(recv.reset(7, 18), Ok(0));

    // The stream has been reset by the peer.
    assert_eq!(recv.read(&mut buf), Err(Error::StreamReset(7)));
    assert_eq!(recv.read(&mut buf), Err(Error::Done));
}

#[test]
fn stream_shutdown_read() {
    let mut recv = RecvBuf::new(20, 10);

    // recv [0, 10)
    assert_eq!(
        recv.write(0, Bytes::from_static(b"Everything"), false),
        Ok(())
    );
    // recv [14, 18)
    assert_eq!(recv.write(14, Bytes::from_static(b"QUIC"), false), Ok(()));

    assert_eq!(recv.data.len(), 2);
    assert_eq!(recv.recv_off(), 18);
    assert_eq!(recv.read_off(), 0);
    assert!(!recv.is_shutdown());

    // Aftet shutdown read:
    //   1) read_off will be updated to recv_off;
    //   2) data will be cleared;
    //   3) is_shutdown will be set to true.
    assert!(recv.shutdown().is_ok());
    assert!(recv.is_shutdown());
    assert!(recv.data.is_empty());
    assert_eq!(recv.recv_off(), 18);
    assert_eq!(recv.read_off(), 18);

    // shutdown read, would not affect the finished state of the stream's receive-side.
    assert!(!recv.is_fin());

    // duplicate shutdown
    assert_eq!(recv.shutdown(), Err(Error::Done));
}

// SendBuf unit tests
// Test SendBuf::new
#[test]
fn send_buf_new() {
    let mut send = SendBuf::new(100);
    assert_eq!(send.capacity().unwrap(), 100);
    assert_eq!(send.data.len(), 0);
    assert_eq!(send.write_off, 0);
    assert_eq!(send.unsent_off, 0);
    assert_eq!(send.unacked_len, 0);
    assert_eq!(send.max_data, 100);
    assert_eq!(send.blocked_at, None);
    assert_eq!(send.fin_off, None);
    assert_eq!(send.shutdown, false);
    assert_eq!(send.acked.len(), 0);
    assert_eq!(send.retransmits.len(), 0);
    assert_eq!(send.error, None);
    assert_eq!(send.read_range(0..10).is_empty(), true);
}

// Test the properties of SendBuf, include data blocks, cap,
// write, write_off, unsent_off, unacked_len, fin_off, error
#[test]
fn send_buf_write_basic_logic() {
    let max_tx_data: usize = 100;
    let mut send = SendBuf::new(max_tx_data as u64);
    assert_eq!(send.data.len(), 0);
    assert_eq!(send.capacity().unwrap(), max_tx_data);

    // Data will be split into consistently sized chunks to avoid fragmentation.
    // Each chunk size is limited by SEND_BUFFER_SIZE(5).

    // Write SEND_BUFFER_SIZE(5) bytes
    let data = Bytes::from("Hello");
    assert_eq!(send.write(data, false), Ok(5));
    assert_eq!(send.unacked_len, 5);
    assert_eq!(send.capacity().unwrap(), max_tx_data.saturating_sub(5));
    // ceil(5 / 5) == 1
    assert_eq!(send.data.len(), 1);

    let data = Bytes::from("Everything over QUIC!");
    assert_eq!(send.write(data, false), Ok(21));
    assert_eq!(send.unacked_len, 26);
    assert_eq!(send.capacity().unwrap(), max_tx_data.saturating_sub(26));
    // ceil(21 / 5) == 5, plus 1 from previous write, equals 6
    assert_eq!(send.data.len(), 6);

    let data = Bytes::from(Bytes::copy_from_slice(&b"a".repeat(100)));
    assert_eq!(send.write(data, true), Ok(74));
    assert_eq!(send.unacked_len, 100);
    assert_eq!(send.capacity().unwrap(), 0);
    // ceil(74 / 5) == 15, plus 6 from previous write, equals 21
    assert_eq!(send.data.len(), 21);
    assert_eq!(send.fin_off, None);

    // Write an empty buffer with fin flag set.
    assert_eq!(send.write(Bytes::new(), true), Ok(0));
    assert_eq!(send.unacked_len, 100);
    assert_eq!(send.capacity().unwrap(), 0);
    assert_eq!(send.data.len(), 21);
    assert_eq!(send.fin_off, Some(100));

    // Can't write more data after fin flag is set.
    assert_eq!(
        send.write(Bytes::from_static(b"b"), true),
        Err(Error::FinalSizeError)
    );
    // Fin flag can't be cancelled after it was set.
    assert_eq!(send.write(Bytes::new(), false), Err(Error::FinalSizeError));
}

// Test for SendBuf::{write, read}
#[test]
fn send_buf_multi_write() {
    let mut send = SendBuf::new(100);
    assert_eq!(send.data.len(), 0);

    let data = Bytes::from("Hello, TQUIC!");
    let first = Bytes::from("Hell");
    let second = Bytes::from("o, T");
    let third = Bytes::from("QUIC!");

    // write [0, 4)
    assert_eq!(send.write(first, false), Ok(4));
    assert_eq!(send.unacked_len, 4);
    assert_eq!(send.data.len(), 1);

    // write [4, 8)
    assert_eq!(send.write(second, false), Ok(4));
    assert_eq!(send.unacked_len, 8);
    assert_eq!(send.data.len(), 2);

    // write [8, 13)
    assert_eq!(send.write(third, true), Ok(5));
    assert_eq!(send.unacked_len, 13);
    assert_eq!(send.data.len(), 3);

    let mut out_buf = [0; 128];
    let (len, fin) = send.read(&mut out_buf[..128]).unwrap();
    assert_eq!(len, 13);
    assert_eq!(fin, true);
    assert_eq!(send.fin_off, Some(13));
    assert_eq!(send.unacked_len, 13);
    assert_eq!(send.unsent_off, 13);
    assert_eq!(out_buf[..13], data[..13]);
}

#[test]
fn send_buf_ack_in_order() {
    let mut send = SendBuf::new(100);
    assert_eq!(send.data.len(), 0);

    let write_data = Bytes::from("Hello, TQUIC!");
    let data = write_data.clone();
    let first = Bytes::from("Hell");
    let second = Bytes::from("o, T");
    let third = Bytes::from("QUIC!");

    assert_eq!(send.write(write_data, true), Ok(13));
    assert_eq!(send.unacked_len, 13);

    let mut out_buf = [0; 128];
    let (len, fin) = send.read(&mut out_buf[..128]).unwrap();
    assert_eq!(len, 13);
    assert_eq!(fin, true);
    assert_eq!(send.fin_off, Some(13));
    assert_eq!(send.unacked_len, 13);
    assert_eq!(send.unsent_off, 13);
    assert_eq!(out_buf[..13], data[..13]);

    // all data is unacked
    assert_eq!(aggregate_unacked(&send), data[..13].to_vec());

    // ack [0, 4]
    send.ack_and_drop(0, 4);
    assert_eq!(send.ack_off(), 4);
    assert_eq!(aggregate_unacked(&send), data[4..13].to_vec());

    // ack [4, 8]
    send.ack_and_drop(4, 4);
    assert_eq!(send.ack_off(), 8);
    assert_eq!(aggregate_unacked(&send), data[8..13].to_vec());

    // ack [8, 13]
    send.ack_and_drop(8, 5);
    assert_eq!(send.ack_off(), 13);
    assert_eq!(aggregate_unacked(&send).is_empty(), true);
}

#[test]
fn send_buf_ack_out_of_order() {
    let mut send = SendBuf::new(100);
    assert_eq!(send.data.len(), 0);

    let write_data = Bytes::from("Hello, TQUIC!");
    let data = write_data.clone();
    let first = Bytes::from("Hell");
    let second = Bytes::from("o, T");
    let third = Bytes::from("QUIC!");

    assert_eq!(send.write(write_data, true), Ok(13));
    assert_eq!(send.unacked_len, 13);

    let mut out_buf = [0; 128];
    assert_eq!(send.read(&mut out_buf[..128]), Ok((13, true)));
    assert_eq!(send.fin_off, Some(13));
    assert_eq!(send.unacked_len, 13);
    assert_eq!(send.unsent_off, 13);
    assert_eq!(out_buf[..13], data[..13]);

    // read nothing because all data is sent and no data need to be retransmitted
    assert_eq!(send.read(&mut out_buf[..128]), Ok((0, true)));

    // all data is unacked
    assert_eq!(aggregate_unacked(&send), data[..13].to_vec());

    // ack [8, 13]
    send.ack_and_drop(8, 5);
    assert_eq!(send.ack_off(), 0);
    assert_eq!(aggregate_unacked(&send), data[..13].to_vec());

    // ack [0, 4]
    send.ack_and_drop(0, 4);
    assert_eq!(send.ack_off(), 4);
    assert_eq!(aggregate_unacked(&send), data[4..13].to_vec());

    // ack [4, 8]
    send.ack_and_drop(4, 4);
    assert_eq!(send.ack_off(), 13);
    assert_eq!(aggregate_unacked(&send).is_empty(), true);
}

#[test]
fn send_buf_spurious_retransmit() {
    let mut send = SendBuf::new(100);
    assert_eq!(send.data.len(), 0);

    let write_data = Bytes::from("Hello, TQUIC!");
    let data = write_data.clone();
    let first = Bytes::from("Hell");
    let second = Bytes::from("o, T");
    let third = Bytes::from("QUIC!");

    assert_eq!(send.write(write_data, true), Ok(13));
    assert_eq!(send.unacked_len, 13);

    let mut out_buf = [0; 128];
    assert_eq!(send.read(&mut out_buf[..128]), Ok((13, true)));
    assert_eq!(send.fin_off, Some(13));
    assert_eq!(send.unacked_len, 13);
    assert_eq!(send.unsent_off, 13);
    assert_eq!(out_buf[..13], data[..13]);

    // read nothing because all data is sent and no data need to be retransmitted
    assert_eq!(send.read(&mut out_buf[..128]), Ok((0, true)));

    // lost [4, 8), retransmit [4, 8)
    send.retransmit(4, 4);
    assert_eq!(send.read(&mut out_buf[..128]), Ok((4, false)));
    assert_eq!(out_buf[..4], data[4..8]);
    // read nothing because all data is sent and no data need to be retransmitted
    assert_eq!(send.read(&mut out_buf[..128]), Ok((0, true)));

    // lost [4, 8) and invalid range [8, 21), retransmit [4, 8)
    send.retransmit(4, 4);
    // invalid retransmit range [8, 21), nothing changed
    send.retransmit(8, 13);
    assert_eq!(send.read(&mut out_buf[..128]), Ok((4, false)));
    assert_eq!(out_buf[..4], data[4..8]);
    // read nothing because all data is sent and no data need to be retransmitted
    assert_eq!(send.read(&mut out_buf[..128]), Ok((0, true)));

    // lost [0, 4) and [8, 13), retransmit [0, 4) and [8, 13)
    send.retransmit(0, 4);
    send.retransmit(8, 5);
    assert_eq!(send.read(&mut out_buf[..128]), Ok((4, false)));
    assert_eq!(out_buf[..4], data[0..4]);
    assert_eq!(send.read(&mut out_buf[..128]), Ok((5, true)));
    assert_eq!(out_buf[..5], data[8..13]);
    // read nothing because all data is sent and no data need to be retransmitted
    assert_eq!(send.read(&mut out_buf[..128]), Ok((0, true)));

    // spurious retransmit [4, 8)
    send.retransmit(4, 4);
    send.ack_and_drop(4, 4);
    assert_eq!(send.read(&mut out_buf[..128]), Ok((0, true)));
    // no data be acked continuously == all data is unacked
    assert_eq!(aggregate_unacked(&send), data[..13].to_vec());

    // spurious retransmit [0, 13)
    send.retransmit(0, 13);
    // ack [4, 8)
    send.ack_and_drop(4, 4);
    // no data be acked continuously == all data is unacked
    assert_eq!(aggregate_unacked(&send), data[..13].to_vec());
    assert_eq!(send.read(&mut out_buf[..128]), Ok((4, false)));
    assert_eq!(out_buf[..4], data[0..4]);
    assert_eq!(send.read(&mut out_buf[..128]), Ok((5, true)));
    assert_eq!(out_buf[..5], data[8..13]);
    // ack [0, 4)
    send.ack_and_drop(0, 4);
    assert_eq!(aggregate_unacked(&send), data[8..13].to_vec());
    assert_eq!(send.read(&mut out_buf[..128]), Ok((0, true)));
    // spurious retransmit [0, 10), effective retransmit [8, 10)
    send.retransmit(0, 10);
    assert_eq!(aggregate_unacked(&send), data[8..13].to_vec());
    assert_eq!(send.read(&mut out_buf[..128]), Ok((2, false)));
    assert_eq!(out_buf[..2], data[8..10]);
    // ack [8, 13)
    send.ack_and_drop(8, 5);
    assert_eq!(aggregate_unacked(&send).is_empty(), true);
    assert_eq!(send.read(&mut out_buf[..128]), Ok((0, true)));
}

#[test]
fn send_buf_retransmit_over_acked_ranges() {
    let mut send = SendBuf::new(100);
    assert_eq!(send.data.len(), 0);

    let write_data = Bytes::from("Everything over QUIC!");
    let data = write_data.clone();

    // Write [0, 21)
    assert_eq!(send.write(write_data, true), Ok(21));
    let mut out_buf = [0; 128];

    // Sent [0, 20)
    assert_eq!(send.read(&mut out_buf[..20]), Ok((20, false)));
    assert_eq!(out_buf[..20], data[..20]);

    // Ack [0, 5) + [10, 20), ack_off: 5
    send.ack_and_drop(0, 5);
    send.ack_and_drop(10, 10);
    assert_eq!(send.ack_off(), 5);

    // Lost [5, 15)
    send.retransmit(5, 10);
    // Ack [5, 11), ack_off: 20
    send.ack_and_drop(5, 6);
    assert_eq!(send.ack_off(), 20);

    assert_eq!(send.read(&mut out_buf[..20]), Ok((1, true)));
    assert_eq!(out_buf[..1], data[20..21]);
}

#[test]
fn send_buf_retransmit_cross_acked_ranges() {
    let mut send = SendBuf::new(100);
    assert_eq!(send.data.len(), 0);

    let write_data = Bytes::from("Everything over QUIC!");
    let data = write_data.clone();

    // Write [0, 21)
    assert_eq!(send.write(write_data, true), Ok(21));
    let mut out_buf = [0; 128];

    // Sent [0, 20)
    assert_eq!(send.read(&mut out_buf[..20]), Ok((20, false)));
    assert_eq!(out_buf[..20], data[..20]);

    // Ack [5, 10) + [15, 18), ack_off: 0
    send.ack_and_drop(5, 5);
    send.ack_and_drop(15, 3);
    assert_eq!(send.acked.peek_min(), Some(5..10));
    assert_eq!(send.ack_off(), 0);

    // 1. The retransmit range is before the first acked range.
    // Lost [0, 1)
    send.retransmit(0, 1);
    assert_eq!(send.retransmits.peek_min(), Some(0..1));
    // Lost [1, 5)
    send.retransmit(1, 4);
    assert_eq!(send.retransmits.pop_min(), Some(0..5));

    // 2. The second half of the retransmit range is covered by the acked range.
    // Lost [1, 6)
    send.retransmit(1, 5);
    assert_eq!(send.retransmits.peek_min(), Some(1..5));
    // Lost [1, 10)
    send.retransmit(1, 9);
    assert_eq!(send.retransmits.pop_min(), Some(1..5));

    // 3. The retransmit range crosses the first acked range.
    // Lost [1, 11)
    send.retransmit(1, 10);
    assert_eq!(send.retransmits.pop_min(), Some(1..5));
    assert_eq!(send.retransmits.pop_min(), Some(10..11));
    // Lost [1, 15)
    send.retransmit(1, 14);
    assert_eq!(send.retransmits.pop_min(), Some(1..5));
    assert_eq!(send.retransmits.pop_min(), Some(10..15));

    // 4. The retransmit range crosses the first acked range and intersects with the second acked range.
    // Lost [1, 16)
    send.retransmit(1, 15);
    assert_eq!(send.retransmits.pop_min(), Some(1..5));
    assert_eq!(send.retransmits.pop_min(), Some(10..15));
    assert!(send.retransmits.is_empty());
    // Lost [1, 18)
    send.retransmit(1, 17);
    assert_eq!(send.retransmits.pop_min(), Some(1..5));
    assert_eq!(send.retransmits.pop_min(), Some(10..15));
    assert!(send.retransmits.is_empty());

    // 5. The retransmit range crosses multiple acked ranges.
    // Lost [1, 19)
    send.retransmit(1, 18);
    assert_eq!(send.retransmits.pop_min(), Some(1..5));
    assert_eq!(send.retransmits.pop_min(), Some(10..15));
    assert_eq!(send.retransmits.pop_min(), Some(18..19));
    assert!(send.retransmits.is_empty());

    // 6. The retransmit range is covered by the acked range fully.
    // Lost [5, 10)
    send.retransmit(5, 5);
    assert!(send.retransmits.is_empty());

    // 7. The first half of the retransmit range is covered by the acked range.
    // Lost [6, 12)
    send.retransmit(6, 6);
    assert_eq!(send.retransmits.pop_min(), Some(10..12));
    // Lost [9, 12)
    send.retransmit(9, 3);
    assert_eq!(send.retransmits.pop_min(), Some(10..12));

    // 8. The retransmit range interacts with multiple acked ranges.
    // Lost [6, 17)
    send.retransmit(6, 11);
    assert_eq!(send.retransmits.pop_min(), Some(10..15));
    assert!(send.retransmits.is_empty());

    // 9. The first half of the retransmit range is covered by the first acked range,
    // and crosses the second acked range.
    // Lost [6, 20)
    send.retransmit(6, 14);
    assert_eq!(send.retransmits.pop_min(), Some(10..15));
    assert_eq!(send.retransmits.pop_min(), Some(18..20));
    assert!(send.retransmits.is_empty());

    // 10. The retransmit range is after the second acked range.
    send.retransmit(18, 1);
    assert_eq!(send.retransmits.pop_min(), Some(18..19));
    send.retransmit(18, 2);
    assert_eq!(send.retransmits.pop_min(), Some(18..20));

    assert_eq!(send.read(&mut out_buf[..20]), Ok((1, true)));
    assert_eq!(out_buf[..1], data[20..21]);
}

#[test]
fn send_buf_poll_transmit() {
    let mut send = SendBuf::new(100);

    assert_eq!(
        send.write(Bytes::from_static(b"EverythingOverQUIC"), true),
        Ok(18)
    );

    let mut buf = [0; 18];
    assert_eq!(send.read(&mut buf[0..14]), Ok((14, false)));

    // Lost [0, 5) and [10, 14)
    send.retransmit(0, 5);
    send.retransmit(10, 4);

    // retransmit [0, 5)
    assert_eq!(send.poll_transmit(5), Range { start: 0, end: 5 });
    // retransmit [10, 12)
    assert_eq!(send.poll_transmit(2), Range { start: 10, end: 12 });
    // retransmit [12, 14)
    assert_eq!(send.poll_transmit(2), Range { start: 12, end: 14 });
    // send [14, 18)
    assert_eq!(send.poll_transmit(2), Range { start: 14, end: 16 });
    // send [16, 18)
    assert_eq!(send.poll_transmit(10), Range { start: 16, end: 18 });
}

// Test SendBuf::shutdown
#[test]
fn stream_shutdown_write() {
    // After shutdown, stream send-side is complete and no data can be written.
    // 1. Shutdown directly after creation
    let mut send = SendBuf::new(100);
    assert_eq!(send.shutdown(), Ok((0, 0)));
    assert_eq!(send.is_complete(), true);

    // 2. After writing data, shutdown the stream prematurely before any data is sent.
    let mut send = SendBuf::new(100);
    assert_eq!(
        send.write(Bytes::from_static(b"EverythingOverQUIC"), true),
        Ok(18)
    );
    assert_eq!(send.shutdown(), Ok((0, 18)));
    assert_eq!(send.is_complete(), true);

    // 3. After writing data, shutdown the stream after part of data is sent.
    let mut send = SendBuf::new(100);
    assert_eq!(
        send.write(Bytes::from_static(b"EverythingOverQUIC"), true),
        Ok(18)
    );
    assert_eq!(send.read(&mut [0; 10]), Ok((10, false)));
    assert_eq!(send.shutdown(), Ok((10, 8)));
    assert_eq!(send.is_complete(), true);

    // 4. After writing data, shutdown the stream after all data is sent.
    let mut send = SendBuf::new(100);
    assert_eq!(
        send.write(Bytes::from_static(b"EverythingOverQUIC"), true),
        Ok(18)
    );
    assert_eq!(send.read(&mut [0; 18]), Ok((18, true)));
    assert_eq!(send.shutdown(), Ok((18, 0)));
    assert_eq!(send.is_complete(), true);

    // 5. After writing data, shutdown the stream after all data is sent and acked.
    let mut send = SendBuf::new(100);
    assert_eq!(
        send.write(Bytes::from_static(b"EverythingOverQUIC"), true),
        Ok(18)
    );
    assert_eq!(send.read(&mut [0; 18]), Ok((18, true)));
    send.ack_and_drop(0, 18);
    assert_eq!(send.shutdown(), Ok((18, 0)));
    assert_eq!(send.is_complete(), true);

    // 6. Shutdown duplicate.
    assert_eq!(send.shutdown(), Err(Error::Done));
}

// Aggregates all unacked data in the send buffer.
fn aggregate_unacked(buf: &SendBuf) -> Vec<u8> {
    let mut data = Vec::new();
    for b in buf.data.iter() {
        data.extend_from_slice(&b[..]);
    }
    data
}

#[test]
fn rangebuf_split_off() {
    // Create a RangeBuf with 21 Bytes data.
    let x = b"Everything over QUIC!";
    let mut buf = RangeBuf::new(Bytes::copy_from_slice(x), 10, true);

    // Check the RangeBuf metadata.
    assert_eq!(buf.off, 10);
    assert_eq!(buf.fin, true);
    assert_eq!(buf.data.len(), 21);

    // Check the RangeBuf methods.
    assert_eq!(buf.off(), 10);
    assert_eq!(buf.fin(), true);
    assert_eq!(buf.len(), 21);
    assert_eq!(buf.max_off(), 31);
    assert_eq!(buf.is_empty(), false);

    // Check the RangeBuf slice.
    assert_eq!(buf[..], x[..]);

    // Consuming 5 Bytes from buf.
    // After Consuming, buf == "thing over QUIC!"
    buf.consume(5);

    assert_eq!(buf.off, 15);
    assert_eq!(buf.fin, true);
    assert_eq!(buf.data.len(), 16);

    assert_eq!(buf.off(), 15);
    assert_eq!(buf.fin(), true);
    assert_eq!(buf.len(), 16);
    assert_eq!(buf.max_off(), 31);
    assert_eq!(buf.is_empty(), false);

    assert_eq!(buf[..], x[5..]);

    // Split buffer, new buf contains [at, len), old buf contains [0, at).
    // After splitting, buf == "thing", new_buf == " over QUIC!".
    let mut new_buf = buf.split_off(5);

    assert_eq!(buf.off, 15);
    assert_eq!(buf.fin, false);
    assert_eq!(buf.data.len(), 5);

    assert_eq!(buf.off(), 15);
    assert_eq!(buf.fin(), false);
    assert_eq!(buf.len(), 5);
    assert_eq!(buf.max_off(), 20);
    assert_eq!(buf.is_empty(), false);

    assert_eq!(buf[..], x[5..10]);

    assert_eq!(new_buf.off, 20);
    assert_eq!(new_buf.fin, true);
    assert_eq!(new_buf.data.len(), 11);

    assert_eq!(new_buf.off(), 20);
    assert_eq!(new_buf.fin(), true);
    assert_eq!(new_buf.len(), 11);
    assert_eq!(new_buf.max_off(), 31);
    assert_eq!(new_buf.is_empty(), false);

    assert_eq!(new_buf[..], x[10..]);

    // Consuming 5 Bytes data from new_buf.
    // After Consuming, new_buf == " QUIC!".
    new_buf.consume(5);

    assert_eq!(new_buf.off, 25);
    assert_eq!(new_buf.fin, true);
    assert_eq!(new_buf.data.len(), 6);

    assert_eq!(new_buf.off(), 25);
    assert_eq!(new_buf.fin(), true);
    assert_eq!(new_buf.len(), 6);
    assert_eq!(new_buf.max_off(), 31);
    assert_eq!(new_buf.is_empty(), false);

    assert_eq!(new_buf[..], x[15..]);

    // Split buffer again, new buf contains [at, len), old buf contains [0, at).
    // After splitting, new_buf == " ", new_new_buf == "QUIC!".
    let mut new_new_buf = new_buf.split_off(1);

    assert_eq!(new_buf.off, 25);
    assert_eq!(new_buf.fin, false);
    assert_eq!(new_buf.data.len(), 1);

    assert_eq!(new_buf.off(), 25);
    assert_eq!(new_buf.fin(), false);
    assert_eq!(new_buf.len(), 1);
    assert_eq!(new_buf.max_off(), 26);
    assert_eq!(new_buf.is_empty(), false);

    assert_eq!(new_buf[..], x[15..16]);

    assert_eq!(new_new_buf.off, 26);
    assert_eq!(new_new_buf.fin, true);
    assert_eq!(new_new_buf.data.len(), 5);

    assert_eq!(new_new_buf.off(), 26);
    assert_eq!(new_new_buf.fin(), true);
    assert_eq!(new_new_buf.len(), 5);
    assert_eq!(new_new_buf.max_off(), 31);
    assert_eq!(new_new_buf.is_empty(), false);

    assert_eq!(new_new_buf[..], x[16..]);

    // Consuming 5 Bytes data from new_new_buf.
    // After Consuming, new_new_buf == "".
    new_new_buf.consume(5);

    assert_eq!(new_new_buf.off, 31);
    assert_eq!(new_new_buf.fin, true);
    assert_eq!(new_new_buf.data.len(), 0);

    assert_eq!(new_new_buf.off(), 31);
    assert_eq!(new_new_buf.fin(), true);
    assert_eq!(new_new_buf.len(), 0);
    assert_eq!(new_new_buf.max_off(), 31);
    assert_eq!(new_new_buf.is_empty(), true);

    assert_eq!(&new_new_buf[..], b"");
}

#[test]
fn rangebuf_split_to() {
    // Create a RangeBuf with 21 Bytes data.
    let x = b"Everything over QUIC!";
    let mut buf = RangeBuf::new(Bytes::copy_from_slice(x), 10, true);

    // Check the RangeBuf metadata.
    assert_eq!(buf.off, 10);
    assert_eq!(buf.fin, true);
    assert_eq!(buf.data.len(), 21);

    // Check the RangeBuf methods.
    assert_eq!(buf.off(), 10);
    assert_eq!(buf.fin(), true);
    assert_eq!(buf.len(), 21);
    assert_eq!(buf.max_off(), 31);
    assert_eq!(buf.is_empty(), false);

    // Check the RangeBuf slice.
    assert_eq!(buf[..], x[..]);

    // Advance 5 Bytes from buf.
    // After advancing, buf == "thing over QUIC!"
    buf.advance(5);

    assert_eq!(buf.off, 15);
    assert_eq!(buf.fin, true);
    assert_eq!(buf.data.len(), 16);

    assert_eq!(buf.off(), 15);
    assert_eq!(buf.fin(), true);
    assert_eq!(buf.len(), 16);
    assert_eq!(buf.max_off(), 31);
    assert_eq!(buf.is_empty(), false);

    assert_eq!(buf[..], x[5..]);

    // Split buffer, old buf contains [at, len), new buf contains [0, at).
    // After splitting, new_buf == "thing", buf == " over QUIC!".
    let new_buf = buf.split_to(5);

    assert_eq!(new_buf.off, 15);
    assert_eq!(new_buf.fin, false);
    assert_eq!(new_buf.data.len(), 5);

    assert_eq!(new_buf.off(), 15);
    assert_eq!(new_buf.fin(), false);
    assert_eq!(new_buf.len(), 5);
    assert_eq!(new_buf.max_off(), 20);
    assert_eq!(new_buf.is_empty(), false);

    assert_eq!(new_buf[..], x[5..10]);

    assert_eq!(buf.off, 20);
    assert_eq!(buf.fin, true);
    assert_eq!(buf.data.len(), 11);

    assert_eq!(buf.off(), 20);
    assert_eq!(buf.fin(), true);
    assert_eq!(buf.len(), 11);
    assert_eq!(buf.max_off(), 31);
    assert_eq!(buf.is_empty(), false);

    assert_eq!(buf[..], x[10..]);

    // Advance 5 Bytes data from buf.
    // After advancing, buf == " QUIC!".
    buf.advance(5);

    assert_eq!(buf.off, 25);
    assert_eq!(buf.fin, true);
    assert_eq!(buf.data.len(), 6);

    assert_eq!(buf.off(), 25);
    assert_eq!(buf.fin(), true);
    assert_eq!(buf.len(), 6);
    assert_eq!(buf.max_off(), 31);
    assert_eq!(buf.is_empty(), false);

    assert_eq!(buf[..], x[15..]);

    // Split buffer again, old buf contains [at, len), new buf contains [0, at).
    // After splitting, new_buf == " ", buf == "QUIC!".
    let new_buf = buf.split_to(1);

    assert_eq!(new_buf.off, 25);
    assert_eq!(new_buf.fin, false);
    assert_eq!(new_buf.data.len(), 1);

    assert_eq!(new_buf.off(), 25);
    assert_eq!(new_buf.fin(), false);
    assert_eq!(new_buf.len(), 1);
    assert_eq!(new_buf.max_off(), 26);
    assert_eq!(new_buf.is_empty(), false);

    assert_eq!(new_buf[..], x[15..16]);

    assert_eq!(buf.off, 26);
    assert_eq!(buf.fin, true);
    assert_eq!(buf.data.len(), 5);

    assert_eq!(buf.off(), 26);
    assert_eq!(buf.fin(), true);
    assert_eq!(buf.len(), 5);
    assert_eq!(buf.max_off(), 31);
    assert_eq!(buf.is_empty(), false);

    assert_eq!(buf[..], x[16..]);

    // Advance 5 Bytes data from buf.
    // After advancing, buf == "".
    buf.advance(5);

    assert_eq!(buf.off, 31);
    assert_eq!(buf.fin, true);
    assert_eq!(buf.data.len(), 0);

    assert_eq!(buf.off(), 31);
    assert_eq!(buf.fin(), true);
    assert_eq!(buf.len(), 0);
    assert_eq!(buf.max_off(), 31);
    assert_eq!(buf.is_empty(), true);

    assert_eq!(&buf[..], b"");
}
