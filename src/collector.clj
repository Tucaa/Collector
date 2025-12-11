(ns collector
  (:gen-class)
  (:require [clojure.java.io :as io])
  (:import [java.util Base64]
           [java.nio ByteBuffer ByteOrder]))

;Konvertovanje bajtova u hexadecimalni string
(defn convert_bytes_hex [array len]
  (apply str (map #(format "%02x" %) (take len array))))

;Konvertovanje bajtovau Base 64 string
(defn convert_bytes_base64 [array len]
  (let [encoder (Base64/getEncoder)]
    (.encodeToString encoder (java.util.Arrays/copyOf array 0 len))))


;F-ja koja cita podatke iz pcap fajla (resiti import) za sada samo binarni format dok ne resis problem sa citanjem preko io.pkts
(defn raw_file [file]
  (with-open [in (io/input-stream file)]
    (loop [buffer (byte-array 4096)]
      (let [n (.read in buffer)]
        (when (pos? n)
          (println (str "Hexadecimal" convert_bytes_hex buffer n))
          (println (str "Base64 " convert_bytes_base64 buffer n))
          ;(println (String. buffer 0 n "ISO-8859-1"))
          (recur buffer))))))

;Funkcija za citanje 32 bitnih podataka

(defn read32 [buffer byte_ord]
  (let [unit (ByteBuffer/wrap buffer)]
    (.order unit byte_ord)
    ;Mora da se konverturje u logn sa samo .getInt unit je bacao integer overflow
    (bit-and (long (.getInt unit)) 0xFFFFFFFF)))

;Funkcija za citanje 16 bitnih podataka
(defn read16 [buffer byte_ord]
  (let [unit (ByteBuffer/wrap buffer)]
    (.order unit byte_ord)
    ;Mora da se konverturje u logn sa samo .getInt unit je bacao integer overflow
    (bit-and (.getShort unit) 0xFFFF)))

;F-ja koja parsira globalni header .pcap fajla
(defn parse_header_global [arr]
  (let [header (byte-array 24)
        n (.read arr header)]
    (when (= n 24)
      (let [read (read32 (java.util.Arrays/copyOfRange header 0 4) ByteOrder/LITTLE_ENDIAN)
            byte_ord (if (or (= read 0xa1b2c3d4) (= read 0xa1b23c4d))
                         ByteOrder/LITTLE_ENDIAN
                         ByteOrder/BIG_ENDIAN)]
        {:read read
         :version_major (read16 (java.util.Arrays/copyOfRange header 4 6) byte_ord)
         :network (read32 (java.util.Arrays/copyOfRange header 20 24) byte_ord)
         :byt_order byte_ord}))))

;Parsiranje zaglavlja paketa
(defn parse_header_packet [arr byte_ord]
  (let [header (byte-array 16)
        n (.read arr header)]
    (when (= n 16)
      {:ts_sec (read32 (java.util.Arrays/copyOfRange header 0 4) byte_ord)
       :ts_usec (read32 (java.util.Arrays/copyOfRange header 4 8) byte_ord)
       :incl_len (read32 (java.util.Arrays/copyOfRange header 8 12) byte_ord)
       :orig_len (read32 (java.util.Arrays/copyOfRange header 12 16) byte_ord)})))

;Parsiranje Ethernet sloja
(defn parse_ethernet [data]
  (when (>= (alength data) 14)
    {:dst_mac (apply str (map #(format "%02x:" %) (take 6 data)))
     :src_mac (apply str (map #(format "%02x:" %) (take 6 (drop 6 data))))
     :ethertype (format "0x%04x" (bit-or (bit-shift-left (bit-and (aget data 12) 0xFF) 8)
                                         (bit-and (aget data 13) 0xFF)))
     :payload (java.util.Arrays/copyOfRange data 14 (alength data))}))

;Funkcija koja agregira tot_bytes i koja vraca counter i finalnu agregiranu vrednost
(defn aggregate
  [data]
  (reduce
    (fn [acc item]
      (let [bytes (:tot-bytes item)]
        {:tot_bytes (+ (:tot_bytes acc) bytes)
         :count       (inc (:count acc))}))
    ;Početno stanje akumulatora
    {:tot_bytes 0 :count 0}
    data))

;Funkcija za konvertovanje vrednosti na osnovu definisane jedinice ('KB, MB, GB ...)
;Kasnije modifikovati da dinamicki pronalazi da li su ('KB, MB ili GB)
;Mapirati sa ovom f-jom
(defn convert
  [unit]
  (let [base 1024]
    (case unit
      :KB (/ bytes base)
      :MB (/ bytes (* base base)) ; 1024^2
      :GB (/ bytes (* base base base)) ; 1024^3
      :TB (/ bytes (* base base base base)) ; 1024^4
      )))


(def test_data
  [{:src-ip "192.168.1.100" :protocol :tcp :tot-bytes 1024}
   {:src-ip "10.0.0.5"      :protocol :udp :tot-bytes 512}
   {:src-ip "192.168.1.100" :protocol :icmp :tot-bytes 128}
   {:src-ip "10.0.0.1"      :protocol :tcp :tot-bytes 2048}])



(defn -main
  [& args]

  (def results  (aggregate test_data))

  (println (str "Ulazni podaci: " test_data))
  (println (str "Rezultati: " results))
  ;(def test_pcap (raw_file "D:/Milan/test.pcap"))


  (def test_header (
                    (with-open [arr (io/input-stream "D:/Milan/test2.pcap")]
                      (if-let [header (parse_header_global arr)]
                        (do
                          (println "____GLOBALNI HEADER_____ ")
                          (println (format "Verzija: %d" (:version_major header)))
                          (println (format "Mreza: %d" (:network header)))


                          (println "_______PAKETI_______")
                          (loop [packet_num 1]
                            (when-let [pkt_header (parse_header_packet arr (:byte_order header))]
                              (let [packet_data (byte-array (:incl_len pkt_header))
                                    n (.read arr packet_data)]
                                (when (= n (:incl_len pkt_header))
                                  (println (format "--- Packet #%d ---" packet_num))
                                  (println (format "Timestamp: %d.%06d" (:ts_sec pkt_header) (:ts_usec pkt_header)))
                                  (println (format "Duzina_paketa: %d bytes (captured: %d)"
                                                   (:orig_len pkt_header) (:incl_len pkt_header)))

                          (println "_______Ethernet sloj______")
                            (when-let [eth (parse_ethernet packet_data)]
                              ;Nesto ne valja format treba
                              (println (format "  Ethernet: %s -> %s (Type: %s)"
                                               (.substring (:src_mac eth) 0 (dec (count (:src_mac eth))))
                                               (.substring (:dst_mac eth) 0 (dec (count (:dst_mac eth))))
                                               (:ethertype eth)))

                              (recur (inc packet_num))))))))))))
                       ;(def converted-kb (convert (:total-bytes results) :KB))

  ;(println (str "Konvertovana vrednost (KB): " converted-kb)))
  )
