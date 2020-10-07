/**
 * This file was generated by the Objective Systems ASN1C Compiler
 * (http://www.obj-sys.com).  Version: 7.4.2, Date: 22-Jul-2020.
 */
package dk.alexandra.stormbird.cheque.asnobjects;

import com.objsys.asn1j.runtime.*;

public class ValidityValue extends Asn1Seq {
   private static final long serialVersionUID = 55;
   static {
      _setKey (_AuthenticationFrameworkRtkey._rtkey);
      Asn1Type._setLicLocation(_AuthenticationFrameworkRtkey._licLocation);
   }

   public String getAsn1TypeName()  {
      return "ValidityValue";
   }

   public Time notBefore;
   public Time notAfter;

   public ValidityValue () {
      super();
      init();
   }

   /**
    * This constructor sets all elements to references to the 
    * given objects
    */
   public ValidityValue (
      Time notBefore_,
      Time notAfter_
   ) {
      super();
      notBefore = notBefore_;
      notAfter = notAfter_;
   }

   public void init () {
      notBefore = null;
      notAfter = null;
   }

   public int getElementCount() { return 2; }


   public Object getElementValue(int index){
      switch(index)  {
         case 0: return notBefore;
         case 1: return notAfter;
         default: return null;
      }
   }


   public String getElementName(int index){
      switch(index)  {
         case 0: return "notBefore";
         case 1: return "notAfter";
         default: return null;
      }
   }


   public void decode
      (Asn1BerDecodeBuffer buffer, boolean explicit, int implicitLength)
      throws Asn1Exception, java.io.IOException
   {
      int llen = (explicit) ?
         matchTag (buffer, Asn1Tag.SEQUENCE) : implicitLength;

      init ();

      // decode SEQUENCE

      Asn1BerDecodeContext _context =
         new Asn1BerDecodeContext (buffer, llen);

      IntHolder elemLen = new IntHolder();

      // decode notBefore

      if (!_context.expired()) {
         Asn1Tag tag = buffer.peekTag ();
         if (tag.equals (Asn1Tag.UNIV, Asn1Tag.PRIM, 23) ||
             tag.equals (Asn1Tag.UNIV, Asn1Tag.PRIM, 24))
         {
            buffer.getContext().eventDispatcher.startElement("notBefore", -1);

            this.notBefore = new Time();
            this.notBefore.decode (buffer, true, elemLen.value);

            buffer.getContext().eventDispatcher.endElement("notBefore", -1);
         }
         else throw new Asn1MissingRequiredException (buffer, "notBefore");
      }
      else throw new Asn1MissingRequiredException (buffer, "notBefore");

      // decode notAfter

      if (!_context.expired()) {
         Asn1Tag tag = buffer.peekTag ();
         if (tag.equals (Asn1Tag.UNIV, Asn1Tag.PRIM, 23) ||
             tag.equals (Asn1Tag.UNIV, Asn1Tag.PRIM, 24))
         {
            buffer.getContext().eventDispatcher.startElement("notAfter", -1);

            this.notAfter = new Time();
            this.notAfter.decode (buffer, true, elemLen.value);

            buffer.getContext().eventDispatcher.endElement("notAfter", -1);
         }
         else throw new Asn1MissingRequiredException (buffer, "notAfter");
      }
      else throw new Asn1MissingRequiredException (buffer, "notAfter");

      if (!_context.expired()) {

      }
   }

   public int encode (Asn1BerEncodeBuffer buffer, boolean explicit)
      throws Asn1Exception
   {
      int _aal = 0, len;

      // encode notAfter

      if (this.notAfter != null) {
         buffer.getContext().eventDispatcher.startElement("notAfter", -1);

         len = this.notAfter.encode (buffer, true);
         _aal += len;

         buffer.getContext().eventDispatcher.endElement("notAfter", -1);
      }
      else throw new Asn1MissingRequiredException ("notAfter");

      // encode notBefore

      if (this.notBefore != null) {
         buffer.getContext().eventDispatcher.startElement("notBefore", -1);

         len = this.notBefore.encode (buffer, true);
         _aal += len;

         buffer.getContext().eventDispatcher.endElement("notBefore", -1);
      }
      else throw new Asn1MissingRequiredException ("notBefore");

      if (explicit) {
         _aal += buffer.encodeTagAndLength (Asn1Tag.SEQUENCE, _aal);
      }

      return (_aal);
   }

   public void print (java.io.PrintWriter _out, String _varName, int _level)
   {
      indent (_out, _level);
      _out.println (_varName + " {");
      if (notBefore != null) notBefore.print (_out, "notBefore", _level+1);
      if (notAfter != null) notAfter.print (_out, "notAfter", _level+1);
      indent (_out, _level);
      _out.println ("}");
   }

}