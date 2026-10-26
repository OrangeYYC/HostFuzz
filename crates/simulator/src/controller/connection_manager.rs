use crate::{Simulator, controller::ControllerError, entity::l2cap::L2capEntity};
use ble::hci::parameter::{AddrKind, BdAddr};
use std::collections::HashMap;
use tracing::error;

/// Manage the connections and peers
pub struct ConnectionManager<'a> {
    pub next_handle: u16,
    connections: HashMap<u16, L2capEntity<'a>>,
}

impl<'a> ConnectionManager<'a> {
    pub fn new() -> Self {
        Self {
            // Many host stacks reserve 0x0000 as a sentinel in internal state machines.
            // Start from 0x0001 to maximize interoperability across targets.
            next_handle: 1u16,
            connections: HashMap::new(),
        }
    }

    pub fn find_connection(&self, address: &BdAddr, address_type: &AddrKind) -> u16 {
        for (handle, con) in &self.connections {
            if con.addr == *address && con.addr_type == *address_type {
                return *handle;
            }
        }
        0xFFFF
    }

    /// creates a new channel for `peer` and return its channel id
    pub fn create_connection(
        &mut self,
        simulator: &'a Simulator,
        address: BdAddr,
        address_type: AddrKind,
        local_addr: BdAddr,
        local_addr_type: AddrKind,
        host_role_is_central: bool,
    ) -> Result<u16, ControllerError> {
        self.create_connection_with_local(simulator, address, address_type, local_addr, local_addr_type, host_role_is_central)
    }

    /// creates a new channel for `peer` with explicit local address context.
    pub fn create_connection_with_local(
        &mut self,
        simulator: &'a Simulator,
        address: BdAddr,
        address_type: AddrKind,
        local_addr: BdAddr,
        local_addr_type: AddrKind,
        host_role_is_central: bool,
    ) -> Result<u16, ControllerError> {
        let handle = self.next_handle;
        self.next_handle += 1;

        // the largets connection handle is 0x0EFF, we should not reach this, so we panic here
        if self.next_handle == 0x0F00 {
            error!("reach the limit of the channels");
            return Err(ControllerError::RequestCrash);
        }
        if self.find_connection(&address, &address_type) != 0xFFFF {
            return Ok(0xFFFF);
        }
        self.connections.insert(
            handle,
            L2capEntity::new(simulator, address, address_type, handle, local_addr, local_addr_type, host_role_is_central),
        );
        Ok(handle)
    }

    /// gets the reference of the peer with connection `handle`
    pub fn get_connection(&'a self, handle: u16) -> Option<&'a L2capEntity<'a>> {
        self.connections.get(&handle)
    }

    /// gets the mutable reference of the peer with connection `handle`
    pub fn get_connection_mut(&mut self, handle: u16) -> Option<&mut L2capEntity<'a>> {
        self.connections.get_mut(&handle)
    }

    /// Returns true when there is no active connection.
    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }

    /// Returns the smallest active connection handle.
    pub fn first_handle(&self) -> Option<u16> {
        self.connections.keys().copied().min()
    }

    /// Ask each active peer to produce idle-time interaction packets when applicable.
    pub fn drive_idle_peers(&mut self) -> bool {
        let mut progressed = false;
        for peer in self.connections.values_mut() {
            progressed |= peer.on_idle_tick();
        }
        progressed
    }

    /// remove the connection
    pub fn remove_connection(&mut self, handle: u16) {
        self.connections.remove(&handle);
    }
}
