import React from 'react';
import { Navbar, Nav } from 'react-bootstrap';
import { Link } from 'react-router-dom';

export default function Footer() {
  const currentYear = new Date().getFullYear();
  return (
    <Navbar bg="dark" variant="dark" style={{"bottom":"0px",padding:"40px",color:"white","textAlign":"center",marginLeft:"auto",marginRight:"auto"}}>
     
      <Nav className="mr-auto" style={{"textAlign":"center"}}>
        <Nav.Link as={Link} to="/cart"style={{"textAlign":"center"}}>Cart</Nav.Link>
        <Nav.Link as={Link} to="/products"style={{"textAlign":"center"}}>Products</Nav.Link>
        <Nav.Link as={Link} to="/categories" style={{"textAlign":"center"}}>Categories</Nav.Link>
      </Nav>
      <span className="text-muted" style={{"textAlign":"center",color:"white"}}>
        &copy; {currentYear} Grocery Store. All rights reserved.
      </span>
    </Navbar>
  );
}
