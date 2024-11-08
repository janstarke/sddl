import { useId, useState, Fragment } from 'react'

import { convert } from "sddl4web";
import Button from "react-bootstrap/Button";
import Form from 'react-bootstrap/Form';
import Row from 'react-bootstrap/Row';
import Col from 'react-bootstrap/Col';
import Alert from 'react-bootstrap/Alert';
import Tab from 'react-bootstrap/Tab';
import Tabs from 'react-bootstrap/Tabs';
import Table from 'react-bootstrap/Table';
import Accordion from 'react-bootstrap/Accordion';
import 'bootstrap/dist/css/bootstrap.min.css';
import { JsonView, allExpanded, darkStyles, defaultStyles } from 'react-json-view-lite';

function App() {
  const [count, setCount] = useState(0)
  const [sddl, setSddl] = useState('O:BAG:BAD:P(A;CIOI;GRGX;;;BU)(A;CIOI;GA;;;BA)(A;CIOI;GA;;;SY)(A;CIOI;GA;;;CO)S:P(AU;FA;GR;;;WD)');
  const [sid, setSid] = useState('S-1-5-21-1004336348-1177238915-682003330-512');
  const [json, setJson] = useState(null);
  const [lastError, setLastError] = useState(null);

  const [owner, setOwner] = useState(null);
  const [group, setGroup] = useState(null);
  const [flags, setFlags] = useState('');
  const [dacl, setDacl] = useState(null);
  const [sacl, setSacl] = useState(null);

  function handleSddlChange(e) {
    setSddl(e.target.value);
  }

  function handleSidChange(e) {
    setSid(e.target.value);
  }

  function convertSddl() {
    try {
      const json = JSON.parse(convert(sddl, sid))
      setJson(json);
      setOwner(json.owner);
      setGroup(json.group);
      setFlags(json.flags);
      setDacl(json.dacl);
      setSacl(json.sacl);

      setLastError(null);
    } catch (e) {
      setLastError(e);
      setJson(null);
    }
  }

  function label_and_text(label, text) {
    if (text["well-known-name"] === null) {
      return (
        <Form.Group as={Row} className="mb-3" >
          <Form.Label column sm={2}>{label}</Form.Label>
          <Col sm={10}>
            <Form.Control type="text" value={text.sid} readOnly />
          </Col>
        </Form.Group>
      )
    } else {
      return (
        <Form.Group as={Row} className="mb-3" >
          <Form.Label column sm={2}>{label}</Form.Label>
          <Col sm={6}>
            <Form.Control type="text" value={text.sid} readOnly />
          </Col>
          <Col sm={4}>
            <Form.Text>{"(" + text["well-known-name"] + ")"}</Form.Text>
          </Col>
        </Form.Group>
      )
    }
  }

  function render_control_flags(flags) {
    const flag_names = [
      "OwnerDefaulted",
      "GroupDefaulted",
      "DiscretionaryAclPresent",
      "DiscretionaryAclDefaulted",
      "SystemAclPresent",
      "SystemAclDefaulted",
      "DiscretionaryAclUntrusted",
      "ServerSecurity",
      "DiscretionaryAclAutoInheritRequired",
      "SystemAclAutoInheritRequired",
      "DiscretionaryAclAutoInherited",
      "SystemAclAutoInherited",
      "DiscretionaryAclProtected",
      "SystemAclProtected",
      "RMControlValid",
      "SelfRelative",
    ];
    return (
      <>
        {flag_names.map((f) => <Form.Check disabled type="checkbox" label={f} checked={flags.includes(f)} />)}
      </>
    )
  }

  function render_ace_flags(flags) {
    const flag_names = [
      "CONTAINER_INHERIT_ACE",
      "FAILED_ACCESS_ACE_FLAG",
      "INHERIT_ONLY_ACE",
      "INHERITED_ACE",
      "NO_PROPAGATE_INHERIT_ACE",
      "OBJECT_INHERIT_ACE",
      "SUCCESSFUL_ACCESS_ACE_FLAG",
      "CRITICAL",
      "TRUST_PROTECTED_FILTER",
    ];
    return (
      <>
        {flag_names.map((f) => <Form.Check disabled type="checkbox" label={f} checked={flags.includes(f)} />)}
      </>
    )
  }

  function render_mask(mask) {
    const mask_names = [
      "GENERIC_READ",
      "GENERIC_WRITE",
      "GENERIC_EXECUTE",
      "GENERIC_ALL",
      "MAXIMUM_ALLOWED",
      "ACCESS_SYSTEM_SECURITY",
      "SYNCHRONIZE",
      "WRITE_OWNER",
      "WRITE_DACL",
      "READ_CONTROL",
      "DELETE",
      "CONTROL_ACCESS",
      "LIST_OBJECT",
      "DELETE_TREE",
      "WRITE_PROPERTY",
      "READ_PROPERTY",
      "SELF_WRITE",
      "LIST_CHILDREN",
      "DELETE_CHILD",
      "CREATE_CHILD"
    ];

    return (
      <>
        {mask_names.map((f) => <Form.Check disabled type="checkbox" label={f} checked={mask.includes(f)} />)}
      </>
    )
  }

  function format_sid(s) {
    if (s["well-known-name"] === null) {
      return s.sid;
    } else {
      return s.sid + " (" + s["well-known-name"] + ")";
    }
  }

  function ace_table_line(ace) {
    const ace_type = Object.entries(ace)[0][0];
    const ace_data = Object.entries(ace)[0][1];
    const ace_flags = render_ace_flags(ace_data.header.ace_flags);
    const ace_mask = render_mask(ace_data.header.mask);
    const ace_sid = format_sid(ace_data.sid);
    return (
      <tr>
        <td>{ace_type}</td>
        <td>
          <Accordion defaultActiveKey="0" flush>
            <Accordion.Item eventKey="1">
              <Accordion.Header>{ace_data.header.ace_flags}</Accordion.Header>
              <Accordion.Body>{ace_flags}</Accordion.Body>
            </Accordion.Item>
          </Accordion>
        </td>
        <td>
          <Accordion defaultActiveKey="0" flush>
            <Accordion.Item eventKey="1">
              <Accordion.Header>{ace_data.header.mask}</Accordion.Header>
              <Accordion.Body>{ace_mask}</Accordion.Body>
            </Accordion.Item>
          </Accordion>
        </td>
        <td>{ace_sid}</td>
      </tr>
    )
  }

  function acl_list(acl) {
    const listItems = acl.ace_list.map(ace_table_line);

    return (
      <Table striped bordered hover>
        <thead>
          <tr>
            <th>ACE Type</th>
            <th>Flags</th>
            <th>Mask</th>
            <th>Sid</th>
          </tr>
        </thead>
        <tbody>
          {listItems}
        </tbody>
      </Table>
    );
  }

  return (
    <>
      <div className="container py-4 px-3 mx-auto">
        <h1>Online SDDL Decoder</h1>
        <Form>
          <Form.Group className="mb-3">
            <Row className="mb-3">
              <Form.Group>
                <Form.Label>SDDL String</Form.Label>
                <Form.Control type="text" aria-describedby="sddlHelpBlock" value={sddl} onChange={handleSddlChange} />
                <Form.Text id="sddlHelpBlock" muted>
                  Place some SDDL (Security Descriptor Description Language) string
                </Form.Text>
              </Form.Group>
            </Row>

            <Row className="mb-3">
              <Form.Group>
                <Form.Label>Domain SID</Form.Label>
                <Form.Control type="text" aria-describedby="sidHelpBlock" value={sid} onChange={handleSidChange} />
                <Form.Text id="sidHelpBlock" muted>
                  Place any SID from the domain here. This is required to find the domain RID
                </Form.Text>
              </Form.Group></Row>

          </Form.Group>

          <Row className="mb-3">
            <Button id="convert" className="btn btn-primary" onClick={convertSddl}>Decode</Button>
          </Row>

          {lastError === null ? null :
            <Row className="mb-3"><Alert variant="danger">{lastError}</Alert></Row>}

          {json === null ? null :
            <Form.Group>

              <Form.Group as={Row} className="mb-3" >
                <Form.Label column sm={2}>Flags</Form.Label>
                <Col sm={10}><Accordion defaultActiveKey="0" flush>
                  <Accordion.Item eventKey="1">
                    <Accordion.Header>{flags}</Accordion.Header>
                    <Accordion.Body>{render_control_flags(flags)}</Accordion.Body>
                  </Accordion.Item>
                </Accordion>
                </Col>
              </Form.Group>

              {label_and_text("Owner", owner)}
              {label_and_text("Group", group)}
              <Tabs
                id="uncontrolled-tab-example"
                className="mb-3"
              >
                <Tab eventKey="dacl" title="DACL">
                  {acl_list(dacl)}
                </Tab>
                <Tab eventKey="sacl" title="SACL">
                  {acl_list(sacl)}
                </Tab>
                <Tab eventKey="raw" title="Raw">
                  <JsonView data={json} shouldExpandNode={allExpanded} style={defaultStyles} clickToExpandNode="true" />
                </Tab>
              </Tabs>
            </Form.Group>
          }
        </Form>
      </div>
    </>
  )
}

export default App
