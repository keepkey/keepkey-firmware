pushd public
for i in $(ls *.proto)
do
    protoc -I. -I/usr/include --plugin=nanopb=/home/tom/src/nanopb/generator/protoc-gen-nanopb --nanopb_out=. $i
done
mv *.pb.c ../local
popd

